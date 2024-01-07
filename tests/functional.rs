use std::str::FromStr;

use bip352::address::SilentPaymentAddress;
use bip352::send::SilentPayment;
use bitcoin::bip32::{ChildNumber, ExtendedPrivKey};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Address, OutPoint};
use bitcoind::bitcoincore_rpc::bitcoin::{Amount, Network};
use bitcoind::bitcoincore_rpc::bitcoincore_rpc_json::{AddressType, CreateRawTransactionInput};
use bitcoind::bitcoincore_rpc::RpcApi;
use bitcoind::BitcoinD;
use miniscript::Descriptor;
use serde_json::Value;

use crate::common::ListDescriptorsResult;

mod common;

#[test]
#[rustfmt::skip]
fn test_me() {
    let secp = Secp256k1::new();

    //
    // Receiver
    //

    let xpriv = ExtendedPrivKey::from_str("tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK").unwrap();

    let scan_keys = xpriv.derive_priv(&secp, &[ChildNumber::Hardened { index: 352 }, ChildNumber::Hardened { index: 1 }, ChildNumber::Hardened { index: 0 }, ChildNumber::Hardened { index: 1 }]).unwrap();
    let scan_key = scan_keys.derive_priv(&secp, &[ChildNumber::Normal { index: 0 }]).unwrap().private_key;

    let spend_keys = xpriv.derive_priv(&secp, &[ChildNumber::Hardened { index: 352 }, ChildNumber::Hardened { index: 1 }, ChildNumber::Hardened { index: 0 }, ChildNumber::Hardened { index: 0 }]).unwrap();
    let spend_key = spend_keys.derive_priv(&secp, &[ChildNumber::Normal { index: 0 }]).unwrap().private_key;

    let spaddress = SilentPaymentAddress::new(spend_key.public_key(&secp), scan_key.public_key(&secp));

    //
    // Sender
    //

    let mut sp = SilentPayment::new(&secp);
    sp.add_recipient(spaddress);

    let client = &BitcoinD::new("/usr/bin/bitcoind").unwrap().client;

    let descs = client.call::<ListDescriptorsResult>("listdescriptors", &[Value::Bool(true)]).unwrap();
    let keys = common::PrivateKeys { keys: common::collect_xprivs(&secp, &descs.descriptors), secp: &secp };

    let addr = client.get_new_address(None, None).unwrap().require_network(Network::Regtest).unwrap();
    client.generate_to_address(101, &addr).unwrap();

    let addr1 = client.get_new_address(None, None).unwrap().require_network(Network::Regtest).unwrap();
    let tx1 = client.send_to_address(&addr1, Amount::from_btc(10.0).unwrap(), None, None, None, None, None, None).unwrap();
    client.generate_to_address(1, &addr).unwrap();
    let tx1 = client.get_transaction(&tx1, None).unwrap().transaction().unwrap();
    let out1 = tx1.output.iter().position(|o| o.script_pubkey == addr1.script_pubkey()).unwrap();
    let outpoint1 = OutPoint::new(tx1.txid(), out1 as u32);
    sp.add_outpoint(outpoint1);
    let (desc1, _) = Descriptor::parse_descriptor(&secp, &client.call::<common::GetAddress>("getaddressinfo", &[Value::String(addr1.to_string())]).unwrap().desc).unwrap();
    if let Some(sec) = keys.for_descriptor(&desc1) {
        sp.add_private_key(sec);
    }

    let addr2 = client.get_new_address(None, Some(AddressType::Bech32m)).unwrap().require_network(Network::Regtest).unwrap();
    let tx2 = client.send_to_address(&addr2, Amount::from_btc(20.0).unwrap(), None, None, None, None, None, None).unwrap();
    client.generate_to_address(1, &addr).unwrap();
    let tx2 = client.get_transaction(&tx2, None).unwrap().transaction().unwrap();
    let out2 = tx2.output.iter().position(|o| o.script_pubkey == addr2.script_pubkey()).unwrap();
    let outpoint2 = OutPoint::new(tx2.txid(), out2 as u32);
    sp.add_outpoint(outpoint2);
    let (desc2, _) = Descriptor::parse_descriptor(&secp, &client.call::<common::GetAddress>("getaddressinfo", &[Value::String(addr2.to_string())]).unwrap().desc).unwrap();
    if let Some(sec) = keys.for_descriptor(&desc2) {
        sp.add_private_key(sec);
    }

    let outputs = sp
        .generate_output_scripts()
        .iter()
        .map(|o| (
            Address::from_script(o, Network::Regtest).unwrap().to_string(),
            Amount::from_btc(0.1).unwrap()
        ))
        .collect();

    println!("{:#?}", outputs);

    let tx = client
        .create_raw_transaction(
            &[
                CreateRawTransactionInput {
                    txid: outpoint1.txid,
                    vout: outpoint1.vout,
                    sequence: None,
                },
                CreateRawTransactionInput {
                    txid: outpoint2.txid,
                    vout: outpoint2.vout,
                    sequence: None,
                },
            ],
            &outputs,
            None,
            None,
        )
        .unwrap();

    let raw = client.sign_raw_transaction_with_wallet(&tx, None, None).unwrap();

    println!("{}", hex::encode(raw.hex));
}
