use std::str::FromStr;

use bip352::address::SilentPaymentAddress;
use bip352::input_public_key;
use bip352::send::SilentPayment;
use bitcoin::bip32::{ChildNumber, ExtendedPrivKey};
use bitcoin::secp256k1::Secp256k1;
use bitcoind::bitcoincore_rpc::bitcoin::{Amount, Network};
use bitcoind::bitcoincore_rpc::bitcoincore_rpc_json::{AddressType, ImportDescriptors, Timestamp};
use bitcoind::bitcoincore_rpc::RpcApi;
use bitcoind::BitcoinD;

#[test]
fn test_me() {
    let secp = Secp256k1::new();

    //
    // Receiver
    //

    let xpriv = ExtendedPrivKey::from_str("tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK").unwrap();

    let scan_keys = xpriv
        .derive_priv(
            &secp,
            &[
                ChildNumber::Hardened { index: 352 },
                ChildNumber::Hardened { index: 1 },
                ChildNumber::Hardened { index: 0 },
                ChildNumber::Hardened { index: 1 },
            ],
        )
        .unwrap();

    let scan_key = scan_keys
        .derive_priv(&secp, &[ChildNumber::Normal { index: 0 }])
        .unwrap()
        .private_key;

    let spend_keys = xpriv
        .derive_priv(
            &secp,
            &[
                ChildNumber::Hardened { index: 352 },
                ChildNumber::Hardened { index: 1 },
                ChildNumber::Hardened { index: 0 },
                ChildNumber::Hardened { index: 0 },
            ],
        )
        .unwrap();

    let spend_key = spend_keys
        .derive_priv(&secp, &[ChildNumber::Normal { index: 0 }])
        .unwrap()
        .private_key;

    let spaddress =
        SilentPaymentAddress::new(spend_key.public_key(&secp), scan_key.public_key(&secp));
    println!(">>>> {}", spaddress);

    //
    // Sender
    //

    let mut sp = SilentPayment::new(&secp);
    sp.add_recipient(spaddress);

    let client = &BitcoinD::new("/usr/bin/bitcoind").unwrap().client;

    let addr = client
        .get_new_address(None, None)
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap();

    client.generate_to_address(101, &addr).unwrap();

    let addr1 = client
        .get_new_address(None, None)
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap();

    let addr2 = client
        .get_new_address(None, Some(AddressType::Bech32m))
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap();

    println!("{}", addr);
    println!("{}", addr1);
    println!("{}", addr2);

    let tx1 = client
        .send_to_address(
            &addr1,
            Amount::from_int_btc(10),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
    let tx2 = client
        .send_to_address(
            &addr2,
            Amount::from_int_btc(20),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();

    client.generate_to_address(1, &addr).unwrap();

    let tx1 = client.get_transaction(&tx1, None).unwrap();

    let tx2 = client
        .get_transaction(&tx2, None)
        .unwrap()
        .transaction()
        .unwrap();

    println!(
        "{:#?}",
        client.list_received_by_address(None, None, None, None)
    )
}
