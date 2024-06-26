use std::collections::HashMap;

use bip352::address::SilentPaymentAddress;
use bip352::receive::Receive;
use bip352::send::SilentPayment;
use bip352::{spend, ScanSecretKey, SpendSecretKey};
use bitcoin::bip32::{ChildNumber, Xpriv};
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::key::TapTweak;
use bitcoin::secp256k1::{Keypair, Secp256k1};
use bitcoin::{Address, OutPoint, PrivateKey, TxOut};
use bitcoind::bitcoincore_rpc::bitcoin::{Amount, Network};
use bitcoind::bitcoincore_rpc::bitcoincore_rpc_json::{AddressType, CreateRawTransactionInput};
use bitcoind::bitcoincore_rpc::RpcApi;
use bitcoind::BitcoinD;
use miniscript::Descriptor;
use rand::random;
use serde_json::Value;

use crate::common::ListDescriptorsResult;

mod common;

#[test]
#[rustfmt::skip]
fn functional_test() {
    let secp = Secp256k1::new();

    //
    // Receiver
    //

    let xpriv = Xpriv::new_master(Network::Regtest, &random::<[u8; 32]>()).unwrap();
    println!("Extended master key: {}", xpriv);

    let scan_keys = xpriv.derive_priv(&secp, &[ChildNumber::Hardened { index: 352 }, ChildNumber::Hardened { index: 1 }, ChildNumber::Hardened { index: 0 }, ChildNumber::Hardened { index: 1 }]).unwrap();
    let scan_key = ScanSecretKey::new(scan_keys.derive_priv(&secp, &[ChildNumber::Normal { index: 0 }]).unwrap().private_key);
    println!("Scan secret key: {}", scan_key.to_secret_key().display_secret());

    let spend_keys = xpriv.derive_priv(&secp, &[ChildNumber::Hardened { index: 352 }, ChildNumber::Hardened { index: 1 }, ChildNumber::Hardened { index: 0 }, ChildNumber::Hardened { index: 0 }]).unwrap();
    let spend_key = SpendSecretKey::new(spend_keys.derive_priv(&secp, &[ChildNumber::Normal { index: 0 }]).unwrap().private_key);
    println!("Spend secret key: {}", spend_key.to_secret_key().display_secret());

    let client = {
        let mut conf = bitcoind::Conf::default();
        conf.args = vec!["-regtest", "-txindex=1", "-fallbackfee=0.0002"];
        &BitcoinD::with_conf("/usr/bin/bitcoind", &conf).unwrap().client
    };

    //
    // Sender
    //

    let mut silent_payment = SilentPayment::new(&secp);
    let spaddress = SilentPaymentAddress::new(spend_key.public_key(&secp), scan_key.public_key(&secp));
    println!("Silent payment address: {}", spaddress.to_bech32(true));

    silent_payment.add_recipient(spaddress);

    // Collect all private keys
    let descs = client.call::<ListDescriptorsResult>("listdescriptors", &[Value::Bool(true)]).unwrap();
    let keys = common::PrivateKeys { keys: common::collect_xprivs(&secp, &descs.descriptors), secp: &secp };

    // Get some money
    let addr = client.get_new_address(None, None).unwrap().require_network(Network::Regtest).unwrap();
    client.generate_to_address(101, &addr).unwrap();

    // Create one output (P2WPKH) and use it as one input for silent payment
    let addr1 = client.get_new_address(None, Some(AddressType::Bech32)).unwrap().require_network(Network::Regtest).unwrap();
    let tx1 = client.send_to_address(&addr1, Amount::from_btc(2.0).unwrap(), None, None, None, None, None, None).unwrap();
    client.generate_to_address(1, &addr).unwrap();
    let tx1 = client.get_transaction(&tx1, None).unwrap().transaction().unwrap();
    println!("Transaction for input 1: {}", serialize_hex(&tx1));
    let out1 = tx1.output.iter().position(|o| o.script_pubkey == addr1.script_pubkey()).unwrap() as u32;
    silent_payment.add_outpoint(OutPoint::new(tx1.compute_txid(), out1));
    let (desc1, _) = Descriptor::parse_descriptor(&secp, &client.call::<common::GetAddress>("getaddressinfo", &[Value::String(addr1.to_string())]).unwrap().desc).unwrap();
    if let Some(sec) = keys.for_descriptor(&desc1) {
        silent_payment.add_private_key(sec);
    }

    // Create second (P2TR) output and use it as second input for silent payment
    let addr2 = client.get_new_address(None, Some(AddressType::Bech32m)).unwrap().require_network(Network::Regtest).unwrap();
    let tx2 = client.send_to_address(&addr2, Amount::from_btc(4.0).unwrap(), None, None, None, None, None, None).unwrap();
    client.generate_to_address(1, &addr).unwrap();
    let tx2 = client.get_transaction(&tx2, None).unwrap().transaction().unwrap();
    println!("Transaction for input 2: {}", serialize_hex(&tx2));
    let out2 = tx2.output.iter().position(|o| o.script_pubkey == addr2.script_pubkey()).unwrap() as u32;
    silent_payment.add_outpoint(OutPoint::new(tx2.compute_txid(), out2));
    let (desc2, _) = Descriptor::parse_descriptor(&secp, &client.call::<common::GetAddress>("getaddressinfo", &[Value::String(addr2.to_string())]).unwrap().desc).unwrap();
    if let Some(sec) = keys.for_descriptor(&desc2) {
        let sec = Keypair::from_secret_key(&secp, &sec).tap_tweak(&secp, None).to_inner();
        silent_payment.add_taproot_private_key(sec);
    }

    // Create third output (P2PKH) and use it as third input for silent payment
    let addr3 = client.get_new_address(None, Some(AddressType::Legacy)).unwrap().require_network(Network::Regtest).unwrap();
    let tx3 = client.send_to_address(&addr3, Amount::from_btc(6.0).unwrap(), None, None, None, None, None, None).unwrap();
    client.generate_to_address(1, &addr).unwrap();
    let tx3 = client.get_transaction(&tx3, None).unwrap().transaction().unwrap();
    println!("Transaction for input 3: {}", serialize_hex(&tx3));
    let out3 = tx3.output.iter().position(|o| o.script_pubkey == addr3.script_pubkey()).unwrap() as u32;
    silent_payment.add_outpoint(OutPoint::new(tx3.compute_txid(), out3));
    let (desc3, _) = Descriptor::parse_descriptor(&secp, &client.call::<common::GetAddress>("getaddressinfo", &[Value::String(addr3.to_string())]).unwrap().desc).unwrap();
    if let Some(sec) = keys.for_descriptor(&desc3) {
        silent_payment.add_private_key(sec);
    }

    // Create fourth output (P2SH-P2WPKH) and use it as fourth input for silent payment
    let addr4 = client.get_new_address(None, Some(AddressType::P2shSegwit)).unwrap().require_network(Network::Regtest).unwrap();
    let tx4 = client.send_to_address(&addr4, Amount::from_btc(8.0).unwrap(), None, None, None, None, None, None).unwrap();
    client.generate_to_address(1, &addr).unwrap();
    let tx4 = client.get_transaction(&tx4, None).unwrap().transaction().unwrap();
    println!("Transaction for input 4: {}", serialize_hex(&tx4));
    let out4 = tx4.output.iter().position(|o| o.script_pubkey == addr4.script_pubkey()).unwrap() as u32;
    silent_payment.add_outpoint(OutPoint::new(tx4.compute_txid(), out4));
    let (desc4, _) = Descriptor::parse_descriptor(&secp, &client.call::<common::GetAddress>("getaddressinfo", &[Value::String(addr4.to_string())]).unwrap().desc).unwrap();
    if let Some(sec) = keys.for_descriptor(&desc4) {
        silent_payment.add_private_key(sec);
    }

    // Collect output scripts for silent payment
    let outputs = silent_payment
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
                CreateRawTransactionInput { txid: tx1.compute_txid(), vout: out1, sequence: None },
                CreateRawTransactionInput { txid: tx2.compute_txid(), vout: out2, sequence: None },
                CreateRawTransactionInput { txid: tx3.compute_txid(), vout: out3, sequence: None },
                CreateRawTransactionInput { txid: tx4.compute_txid(), vout: out4, sequence: None },
            ],
            &outputs,
            None,
            None,
        )
        .unwrap();

    let funded = client.fund_raw_transaction(&tx, None, None).unwrap();
    let signed = client.sign_raw_transaction_with_wallet(&funded.hex, None, None).unwrap();
    let txid = client.send_raw_transaction(&signed.hex).unwrap();
    client.generate_to_address(101, &addr).unwrap();

    //
    // Receiver
    //

    // Scan

    let receive = Receive::new(scan_key, spend_key.public_key(&secp), vec![]);

    let tx = client.get_raw_transaction(&txid, None).unwrap();
    println!("Transaction with silent payment: {}", serialize_hex(&tx));
    let prevs: HashMap<OutPoint, TxOut> = tx.input.iter().map(|vin| {
        let prev_tx = client.get_raw_transaction(&vin.previous_output.txid, None).unwrap();
        (vin.previous_output, prev_tx.output[vin.previous_output.vout as usize].clone())
    }).collect();

    let outputs = receive.scan_transaction(&prevs, &tx);
    let output = outputs.iter().next().unwrap();

    // Spend

    let vout = tx.output.iter().position(|o| o.value.to_sat() == 10_000_000).unwrap() as u32;
    let addr4 = client.get_new_address(None, None).unwrap().require_network(Network::Regtest).unwrap();
    let spending_tx = client
        .create_raw_transaction(
            &[CreateRawTransactionInput { txid: tx.compute_txid(), vout, sequence: None }],
            &[(addr4.to_string(), Amount::from_btc(0.07).unwrap())].into_iter().collect(),
            None,
            None
        ).unwrap();
    let funded = client.fund_raw_transaction(&spending_tx, None, None).unwrap();

    let keypair = spend::signing_keypair(spend_key, scan_key, output.tweak(), output.label()).unwrap();
    let signed = client
        .sign_raw_transaction_with_key(
            &funded.hex,
            &[PrivateKey::new(keypair.secret_key(), Network::Regtest)],
            None,
            None
        ).unwrap();

    let txid = client.send_raw_transaction(&signed.hex).unwrap();
    client.generate_to_address(10, &addr).unwrap();
    let tx = client.get_raw_transaction_info(&txid, None).unwrap().transaction().unwrap();

    assert!(tx.output.iter().any(|o| o.value.to_sat() == (0.07 * 1e8) as u64));
}
