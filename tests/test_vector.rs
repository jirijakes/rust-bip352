use bip352::silent_payment_signing_key;
use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::key::TapTweak;
use bitcoin::secp256k1::{All, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::{OutPoint, ScriptBuf, Txid};
use indexmap::IndexMap;
use serde::Deserialize;
use std::fs::File;
use std::io::BufReader;
use std::str::FromStr;

#[test]
#[cfg(any(feature = "receive", feature = "send"))]
fn bip352_test_vector() {
    let f = File::open("tests/data/send_and_receive_test_vectors.json").unwrap();
    let reader = BufReader::new(f);

    let secp = bitcoin::secp256k1::Secp256k1::new();

    serde_json::from_reader::<_, Vec<Test>>(reader)
        .unwrap()
        .iter()
        .for_each(|t| {
            #[cfg(feature = "receive")]
            test_receiving(&t.receiving, &t.comment, &secp);
            #[cfg(feature = "send")]
            test_sending(&t.sending, &t.comment, &secp);
        });
}

#[cfg(feature = "receive")]
fn test_receiving(receiving: &[Receiving], test: &str, secp: &Secp256k1<All>) {
    use bip352::receive::Scanning;

    receiving.iter().for_each(|r| {
        let spend_key =
            SecretKey::from_slice(&Vec::from_hex(&r.given.spend_priv_key).unwrap()).unwrap();

        let scanning = Scanning::new(
            SecretKey::from_slice(&Vec::from_hex(&r.given.scan_priv_key).unwrap()).unwrap(),
            spend_key.public_key(secp),
            r.given
                .labels
                .values()
                .map(|s| Vec::from_hex(s).unwrap().try_into().unwrap())
                .collect(),
        );

        r.expected
            .addresses
            .iter()
            .zip(scanning.addresses(secp))
            .for_each(|(expected, spa)| assert_eq!(&spa.to_string(), expected, "{test}"));

        let given_outputs = r
            .given
            .outputs
            .iter()
            .map(|o| {
                ScriptBuf::new_v1_p2tr_tweaked(
                    XOnlyPublicKey::from_str(o)
                        .unwrap()
                        .dangerous_assume_tweaked(),
                )
            })
            .collect::<Vec<_>>();

        if let Some(mut builder) = scanning.scan_script_pubkeys(&given_outputs, secp) {
            r.given.outpoints.iter().for_each(|(txid, vout)| {
                builder.add_outpoint(&OutPoint::new(Txid::from_str(txid).unwrap(), *vout));
            });
            r.given.input_pub_keys.iter().for_each(|pk| {
                if pk.len() == 66 {
                    builder.add_public_key(&pk.parse().unwrap());
                } else {
                    builder.add_xonly_public_key(&pk.parse().unwrap());
                }
            });

            let mut found_outputs = builder.xxx();

            r.expected.outputs.iter().for_each(|o| {
                let expected_output = XOnlyPublicKey::from_str(&o.pub_key).unwrap();

                let destination = found_outputs.remove(&expected_output);

                assert!(
                    destination.is_some(),
                    "Could not find `{expected_output}` in `{test}`."
                );

                if let Some(tweak) = destination {
                    // assert_eq!(
                    // hex::encode(tweak.secret_bytes()),
                    // o.priv_key_tweak,
                    // "Private key tweak no equal in `{test}`"
                    // );

                    let keypair = silent_payment_signing_key(spend_key, &tweak, secp).unwrap();
                    let msg = Message::from_slice(
                        sha256::Hash::hash(&"message".to_string().into_bytes()).as_byte_array(),
                    )
                    .unwrap();
                    let aux = sha256::Hash::hash(&"random auxiliary data".to_string().into_bytes())
                        .to_byte_array();

                    let sig = secp.sign_schnorr_with_aux_rand(&msg, &keypair, &aux);
                    assert_eq!(hex::encode(sig.as_ref()), o.signature);
                }
            });

            assert!(
                found_outputs.is_empty(),
                "Found more outputs than expected in `{test}`."
            );
        }
    });
}

#[cfg(feature = "send")]
fn test_sending(sending: &[Sending], test: &str, secp: &Secp256k1<All>) {
    use bip352::send::SilentPayment;

    sending.iter().for_each(|s| {
        let mut payment = SilentPayment::new(secp);
        s.given.recipients.iter().for_each(|(addr, _amount)| {
            payment.add_recipient(addr.parse().unwrap());
        });
        s.given.outpoints.iter().for_each(|(txid, vout)| {
            payment.add_outpoint(OutPoint::new(txid.parse().unwrap(), *vout));
        });
        s.given
            .input_priv_keys
            .iter()
            .for_each(|(key, is_taproot)| {
                let key = SecretKey::from_slice(&Vec::from_hex(key).unwrap()).unwrap();
                if *is_taproot {
                    payment.add_taproot_private_key(key);
                } else {
                    payment.add_private_key(key);
                }
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

#[derive(Debug, Deserialize)]
struct SendingGiven {
    outpoints: Vec<(String, u32)>,
    input_priv_keys: Vec<(String, bool)>,
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
struct ReceivingGiven {
    outpoints: Vec<(String, u32)>,
    input_pub_keys: Vec<String>,
    bip32_seed: String,
    scan_priv_key: String,
    spend_priv_key: String,
    labels: IndexMap<String, String>,
    outputs: Vec<String>,
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
    supports_labels: bool,
    given: ReceivingGiven,
    expected: ReceivingExpected,
}

#[derive(Debug, Deserialize)]
struct Test {
    comment: String,
    sending: Vec<Sending>,
    receiving: Vec<Receiving>,
}
