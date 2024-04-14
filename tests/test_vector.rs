use bitcoin::absolute::LockTime;
use bitcoin::consensus::deserialize;
use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::key::{TapTweak, TweakedPublicKey};
use bitcoin::secp256k1::{All, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid};
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
        .for_each(|t| {
            #[cfg(feature = "send")]
            test_sending(&t.sending, &t.comment, &secp);
            #[cfg(feature = "receive")]
            test_receiving(&t.receiving, &t.comment, &secp);
        });
}

#[cfg(feature = "receive")]
fn test_receiving(receiving: &[Receiving], test: &str, secp: &Secp256k1<All>) {
    use std::collections::HashSet;

    use bip352::{label::LabelIndex, receive::Receive, ScanSecretKey, SpendPublicKey};

    receiving.iter().for_each(|r| {
        let spend_key =
            SecretKey::from_slice(&Vec::from_hex(&r.given.key_material.spend_priv_key).unwrap())
                .unwrap();

        let receive = Receive::new(
            ScanSecretKey::new(
                SecretKey::from_slice(&Vec::from_hex(&r.given.key_material.scan_priv_key).unwrap())
                    .unwrap(),
            ),
            SpendPublicKey::new(spend_key.public_key(secp)),
            r.given
                .labels
                .iter()
                .map(|l| LabelIndex::try_from(l).unwrap())
                .collect(),
        );

        let expected_addresses: HashSet<String> = r.expected.addresses.iter().cloned().collect();
        let given_addresses: HashSet<String> = receive
            .addresses(secp)
            .iter()
            .map(|spa| spa.to_bech32(false))
            .collect();
        assert_eq!(given_addresses, expected_addresses, "{test}");

        let prevouts = r
            .given
            .vin
            .iter()
            .map(|vin| {
                (
                    vin.out_point(),
                    TxOut {
                        value: Amount::from_sat(123),
                        script_pubkey: vin.prevout.script_pub_key.hex.clone(),
                    },
                )
            })
            .collect();

        let silent_payment_outputs = receive.scan_transaction(&prevouts, &r.given.to_tx());

        let calculated_outputs = silent_payment_outputs
            .iter()
            .map(|o| o.public_key())
            .collect::<HashSet<_>>();

        let expected_outputs = r
            .expected
            .outputs
            .iter()
            .map(|o| XOnlyPublicKey::from_str(&o.pub_key).unwrap())
            .collect();

        if test.starts_with(
            "Multiple outputs with labels: multiple outputs for labeled address; same recipient",
        ) {
            assert!(
                calculated_outputs.is_subset(&expected_outputs),
                "Found different outputs than expected in `{test}`."
            );
        } else {
            assert_eq!(
                calculated_outputs, expected_outputs,
                "Found different outputs than expected in `{test}`."
            );
        }

        #[cfg(feature = "spend")]
        test_spending(r, &silent_payment_outputs, test, secp);
    });
}

#[cfg(feature = "send")]
fn test_sending(sending: &[Sending], test: &str, secp: &Secp256k1<All>) {
    use std::collections::HashSet;

    use bip352::send::SilentPayment;

    sending.iter().for_each(|s| {
        let mut payment = SilentPayment::new(secp);
        s.given.recipients.iter().for_each(|addr| {
            payment.add_recipient(addr.parse().unwrap());
        });
        s.given.vin.iter().for_each(|vin| {
            payment.add_outpoint(vin.to_txin().previous_output);
            if let Some(_pk) =
                bip352::input_public_key(&vin.prevout.script_pub_key.hex, &vin.to_txin())
            {
                let key = SecretKey::from_slice(
                    &Vec::from_hex(&vin.private_key.clone().unwrap()).unwrap(),
                )
                .unwrap();

                if vin.prevout.script_pub_key.hex.is_p2tr() {
                    payment.add_taproot_private_key(key);
                } else {
                    payment.add_private_key(key);
                }
            }
        });

        let given_scripts = payment
            .generate_output_scripts()
            .into_iter()
            .collect::<HashSet<_>>();

        let expected_scripts = s
            .expected
            .outputs
            .iter()
            .map(|expected_key| {
                ScriptBuf::new_p2tr_tweaked(
                    XOnlyPublicKey::from_str(expected_key)
                        .unwrap()
                        .dangerous_assume_tweaked(),
                )
            })
            .collect();

        if test.starts_with(
            "Multiple outputs with labels: multiple outputs for labeled address; same recipient",
        ) {
            assert!(
                given_scripts.is_subset(&expected_scripts),
                "output script in '{test}'"
            );
        } else {
            assert_eq!(given_scripts, expected_scripts, "output script in '{test}'");
        }
    })
}

#[cfg(feature = "spend")]
fn test_spending(
    receiving: &Receiving,
    silent_payment_outputs: &std::collections::HashSet<bip352::SilentPaymentOutput>,
    test: &str,
    secp: &Secp256k1<All>,
) {
    use bip352::{spend, ScanSecretKey, SpendSecretKey};

    let spend_key = SpendSecretKey::new(
        SecretKey::from_slice(
            &Vec::from_hex(&receiving.given.key_material.spend_priv_key).unwrap(),
        )
        .unwrap(),
    );

    let scan_key = ScanSecretKey::new(
        SecretKey::from_slice(&Vec::from_hex(&receiving.given.key_material.scan_priv_key).unwrap())
            .unwrap(),
    );

    receiving.expected.outputs.iter().for_each(|o| {
        let public_key = XOnlyPublicKey::from_slice(&Vec::from_hex(&o.pub_key).unwrap()).unwrap();

        if let Some(spo) = silent_payment_outputs
            .iter()
            .find(|o| o.public_key() == public_key)
        {
            let keypair =
                spend::signing_keypair(spend_key, scan_key, spo.tweak(), spo.label()).unwrap();

            let msg = Message::from_digest(
                sha256::Hash::hash(&"message".to_string().into_bytes()).to_byte_array(),
            );
            let aux = sha256::Hash::hash(&"random auxiliary data".to_string().into_bytes())
                .to_byte_array();

            let sig = secp.sign_schnorr_with_aux_rand(&msg, &keypair, &aux);
            assert_eq!(
                hex::encode(sig.as_ref()),
                o.signature,
                "Signatures are not the same in '{test}'."
            );
        } else if !test.starts_with(
            "Multiple outputs with labels: multiple outputs for labeled address; same recipient",
        ) {
            panic!("Output {public_key} not found in `{test}`.")
        }
    });
}

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

impl Vin {
    fn out_point(&self) -> OutPoint {
        OutPoint::new(self.txid, self.vout)
    }

    fn to_txin(&self) -> TxIn {
        let w = hex::decode(&self.txinwitness).unwrap();
        TxIn {
            previous_output: self.out_point(),
            script_sig: self.script_sig.clone(),
            sequence: Sequence::MAX,
            witness: deserialize(&w).unwrap_or_default(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct SendingGiven {
    vin: Vec<Vin>,
    recipients: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SendingExpected {
    outputs: Vec<String>,
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
impl ReceivingGiven {
    fn to_tx(&self) -> Transaction {
        let input = self.vin.iter().map(|vin| vin.to_txin()).collect();
        let output = self
            .outputs
            .iter()
            .map(|out| TxOut {
                value: Amount::from_sat(123),
                script_pubkey: ScriptBuf::new_p2tr_tweaked(
                    TweakedPublicKey::dangerous_assume_tweaked(
                        XOnlyPublicKey::from_str(out).unwrap(),
                    ),
                ),
            })
            .collect();
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input,
            output,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ReceivingOutput {
    pub_key: String,
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
