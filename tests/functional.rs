use std::str::FromStr;

use bip352::address::SilentPaymentAddress;
use bip352::input_public_key;
use bip352::receive::Scan;
use bip352::send::SilentPayment;
use bip352::spend::Spend;
use bitcoin::bip32::{ChildNumber, ExtendedPrivKey};
use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
use bitcoin::{Address, OutPoint, PrivateKey};
use bitcoind::bitcoincore_rpc::bitcoin::{Amount, Network};
use bitcoind::bitcoincore_rpc::bitcoincore_rpc_json::CreateRawTransactionInput;
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

    let client = {
        let mut conf = bitcoind::Conf::default();
        conf.args = vec!["-regtest", "-txindex=1", "-fallbackfee=0.0002"];
        &BitcoinD::with_conf("/usr/bin/bitcoind", &conf).unwrap().client
    };

    // Collect all private keys
    let descs = client.call::<ListDescriptorsResult>("listdescriptors", &[Value::Bool(true)]).unwrap();
    let keys = common::PrivateKeys { keys: common::collect_xprivs(&secp, &descs.descriptors), secp: &secp };

    // Get some money
    let addr = client.get_new_address(None, None).unwrap().require_network(Network::Regtest).unwrap();
    client.generate_to_address(101, &addr).unwrap();

    // Create one output and use it as one input for silent payment
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

    // Create second output and use it as second input for silent payment
    // TODO: Change to Bech32m and tapproot
    let addr2 = client.get_new_address(None, None).unwrap().require_network(Network::Regtest).unwrap();
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

    // Collect output scripts for silent payment
    let outputs = sp
        .generate_output_scripts()
        .iter()
        .map(|o| (
            Address::from_script(o, Network::Regtest).unwrap().to_string(),
            Amount::from_btc(0.1).unwrap()
        ))
        .collect();

    // Finish transaction, sign and broadcast
    let tx = client
        .create_raw_transaction(
            &[
                CreateRawTransactionInput { txid: outpoint1.txid, vout: outpoint1.vout, sequence: None },
                CreateRawTransactionInput { txid: outpoint2.txid, vout: outpoint2.vout, sequence: None },
            ],
            &outputs,
            None,
            None,
        )
        .unwrap();

    let funded = client.fund_raw_transaction(&tx, Some(&Default::default()), None).unwrap();
    let signed = client.sign_raw_transaction_with_wallet(&funded.hex, None, None).unwrap();
    let txid = client.send_raw_transaction(&signed.hex).unwrap();
    client.generate_to_address(101, &addr).unwrap();

    //
    // Receiver
    //

    // Scan

    let mut scan = Scan::new(scan_key, spend_key.public_key(&secp), vec![]);

    let tx = client.get_raw_transaction(&txid, None).unwrap();
    tx.input.iter().for_each(|i| { scan.add_outpoint(&i.previous_output); });
    let prevs = tx.input.iter().map(|vin| client.get_raw_transaction(&vin.previous_output.txid, None).unwrap().output[vin.previous_output.vout as usize].script_pubkey.clone()).collect::<Vec<_>>();
    prevs.iter().zip(&tx.input)
        .for_each(|(prevout, input)| if let Some(pk) = input_public_key(prevout, input) {
            scan.add_public_key(&pk);
        });
    tx.output.iter().for_each(|o| { scan.add_tx_out(o); });

    let outputs = scan.xxx();
    let output = outputs.iter().next().unwrap();

    // Spend

    let mut spend = Spend::new();
    tx.input.iter().for_each(|i| { spend.add_outpoint(&i.previous_output); });
    prevs.iter().zip(&tx.input)
        .for_each(|(prevout, input)| if let Some(pk) = input_public_key(prevout, input) {
            spend.add_public_key(&pk);
        });

    let vout = tx.output.iter().position(|o| o.value == 10000000).unwrap() as u32;
    let addr3 = client.get_new_address(None, None).unwrap().require_network(Network::Regtest).unwrap();
    let spending_tx = client
        .create_raw_transaction(
            &[CreateRawTransactionInput { txid: tx.txid(), vout, sequence: None }],
            &[(addr3.to_string(), Amount::from_btc(0.07).unwrap())].into_iter().collect(),
            None,
            None
        ).unwrap();
    let funded = client.fund_raw_transaction(&spending_tx, None, None).unwrap();

    let keypair = spend.signing_keypair(scan_key, spend_key, output.k(), output.label());
    let signed = client
        .sign_raw_transaction_with_key(
            &funded.hex,
            &[PrivateKey::new(keypair.secret_key(), Network::Regtest)],
            None,
            None
        ).unwrap();

    let txid = client.send_raw_transaction(&signed.hex).unwrap();
    client.generate_to_address(10, &addr).unwrap();
    let tx = client.get_raw_transaction_info(&txid, None).unwrap();

    println!("{:?}", tx);
}
