use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::key::TapTweak;
use bitcoin::secp256k1::{All, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::{OutPoint, ScriptBuf, Txid};
use serde::Deserialize;
use std::fs::File;
use std::io::BufReader;
use std::str::FromStr;

#[test]
#[cfg(any(feature = "receive", feature = "send", feature = "spend"))]
fn bip352_test_vector() {
    let f = File::open("tests/data/send_and_receive_test_vectors.json").unwrap();
    let reader = BufReader::new(f);

    let secp = bitcoin::secp256k1::Secp256k1::new();

    serde_json::from_reader::<_, Vec<Test>>(reader)
        .unwrap()
        .iter()
        // .take(1)
        .for_each(|t| {
            // println!("{t:?}");
            // #[cfg(feature = "send")]
            // test_sending(&t.sending, &t.comment, &secp);
            #[cfg(feature = "receive")]
            test_receiving(&t.receiving, &t.comment, &secp);
        });
}

#[cfg(feature = "receive")]
fn test_receiving(receiving: &[Receiving], test: &str, secp: &Secp256k1<All>) {
    use std::collections::HashSet;

    use bip352::receive::Receive;

    receiving.iter().for_each(|r| {
        let spend_key =
            SecretKey::from_slice(&Vec::from_hex(&r.given.key_material.spend_priv_key).unwrap())
                .unwrap();

        let receive = Receive::new(
            SecretKey::from_slice(&Vec::from_hex(&r.given.key_material.scan_priv_key).unwrap())
                .unwrap(),
            spend_key.public_key(secp),
            r.given.labels.clone(),
        );

        let expected_addresses: HashSet<String> = r.expected.addresses.iter().cloned().collect();
        let given_addresses: HashSet<String> = receive
            .addresses(secp)
            .iter()
            .map(|spa| spa.to_string())
            .collect();
        assert_eq!(given_addresses, expected_addresses, "{test}");

        // let mut scanner = receive.new_scanner();

        // r.given.outputs.iter().for_each(|o| {
        //     scanner.add_output_public_key(XOnlyPublicKey::from_str(o).unwrap());
        // });

        // r.given.outpoints.iter().for_each(|(txid, vout)| {
        //     scanner.add_outpoint(&OutPoint::new(Txid::from_str(txid).unwrap(), *vout));
        // });
        // r.given.input_pub_keys.iter().for_each(|pk| {
        //     if pk.len() == 66 {
        //         scanner.add_public_key(&pk.parse().unwrap());
        //     } else {
        //         scanner.add_xonly_public_key(&pk.parse().unwrap());
        //     }
        // });

        // let silent_payment_outputs = scanner.scan();

        // let calculated_outputs = silent_payment_outputs
        //     .iter()
        //     .map(|o| o.public_key())
        //     .collect::<HashSet<_>>();

        // let expected_outputs = r
        //     .expected
        //     .outputs
        //     .iter()
        //     .map(|o| XOnlyPublicKey::from_str(&o.pub_key).unwrap())
        //     .collect();

        // assert_eq!(
        //     calculated_outputs, expected_outputs,
        //     "Found different outputs than expected in `{test}`."
        // );

        // #[cfg(feature = "spend")]
        // test_spending(r, &silent_payment_outputs, test, secp);
    });
}

/*
#[cfg(feature = "send")]
fn test_sending(sending: &[Sending], test: &str, secp: &Secp256k1<All>) {
    use bip352::send::SilentPayment;

    sending.iter().for_each(|s| {
        let mut payment = SilentPayment::new(secp);
        s.given.recipients.iter().for_each(|(addr, _amount)| {
            payment.add_recipient(addr.parse().unwrap());
        });
        s.given.vin.iter().for_each(|vin| {
            payment.add_outpoint(OutPoint::new(vin.txid, vin.vout));
            let key = SecretKey::from_slice(&Vec::from_hex(&vin.private_key.clone().unwrap()).unwrap()).unwrap();
            // if *is_taproot {
                payment.add_taproot_private_key(key);
            // } else {
                // payment.add_private_key(key);
            // }
        });

        payment
            .generate_output_scripts()
            .into_iter()
            .zip(s.expected.outputs.iter())
            .for_each(|(given_script, (expected_key, _))| {
                let expected_script = ScriptBuf::new_v1_p2tr_tweaked(
                    XOnlyPublicKey::from_str(expected_key)
                        .unwrap()
                        .dangerous_assume_tweaked(),
                );
                assert_eq!(given_script, expected_script, "output script in '{test}'");
            });
    })
}
*/
/*
#[cfg(feature = "spend")]
fn test_spending(
    receiving: &Receiving,
    silent_payment_outputs: &std::collections::HashSet<bip352::SilentPaymentOutput>,
    test: &str,
    secp: &Secp256k1<All>,
) {
    use bip352::spend;

    let spend_key =
        SecretKey::from_slice(&Vec::from_hex(&receiving.given.spend_priv_key).unwrap()).unwrap();

    receiving.expected.outputs.iter().for_each(|o| {
        let public_key = XOnlyPublicKey::from_slice(&Vec::from_hex(&o.pub_key).unwrap()).unwrap();

        if let Some(spo) = silent_payment_outputs
            .iter()
            .find(|o| o.public_key() == public_key)
        {
            let keypair = spend::signing_keypair(spend_key, spo.tweak(), spo.label());

            let msg = Message::from_slice(
                sha256::Hash::hash(&"message".to_string().into_bytes()).as_byte_array(),
            )
            .unwrap();
            let aux = sha256::Hash::hash(&"random auxiliary data".to_string().into_bytes())
                .to_byte_array();

            let sig = secp.sign_schnorr_with_aux_rand(&msg, &keypair, &aux);
            assert_eq!(
                hex::encode(sig.as_ref()),
                o.signature,
                "Signatures are not the same in '{test}'."
            );
        } else {
            panic!("Output {public_key} not found in `{test}`.")
        }
    });
}
*/
#[derive(Debug, Deserialize)]
struct ScriptPubKey {
    hex: ScriptBuf,
}

#[derive(Debug, Deserialize)]
struct Prevout {
    #[serde(rename = "scriptPubKey")]
    script_pub_key: ScriptPubKey,
}

#[derive(Debug, Deserialize)]
struct Vin {
    txid: Txid,
    vout: u32,
    #[serde(rename = "scriptSig")]
    script_sig: ScriptBuf,
    txinwitness: String,
    prevout: Prevout,
    private_key: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SendingGiven {
    vin: Vec<Vin>,
    recipients: Vec<(String, f64)>,
}

#[derive(Debug, Deserialize)]
struct SendingExpected {
    outputs: Vec<(String, f64)>,
}

#[derive(Debug, Deserialize)]
struct Sending {
    given: SendingGiven,
    expected: SendingExpected,
}

#[derive(Debug, Deserialize)]
struct KeyMaterial {
    scan_priv_key: String,
    spend_priv_key: String,
}

#[derive(Debug, Deserialize)]
struct ReceivingGiven {
    vin: Vec<Vin>,
    outputs: Vec<String>,
    key_material: KeyMaterial,
    labels: Vec<u32>,
}

#[derive(Debug, Deserialize)]
struct ReceivingOutput {
    pub_key: String,
    priv_key_tweak: String,
    signature: String,
}

#[derive(Debug, Deserialize)]
struct ReceivingExpected {
    addresses: Vec<String>,
    outputs: Vec<ReceivingOutput>,
}

#[derive(Debug, Deserialize)]
struct Receiving {
    given: ReceivingGiven,
    expected: ReceivingExpected,
}

#[derive(Debug, Deserialize)]
struct Test {
    comment: String,
    sending: Vec<Sending>,
    receiving: Vec<Receiving>,
}
