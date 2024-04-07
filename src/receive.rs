use std::collections::{HashMap, HashSet};

use bitcoin::hashes::sha256t::Tag;
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::secp256k1::{
    All, Parity, PublicKey, Scalar, Secp256k1, SecretKey, Signing, Verification, XOnlyPublicKey,
};
use bitcoin::{OutPoint, Script, Transaction, TxOut};

use crate::address::SilentPaymentAddress;
use crate::{
    input_public_key, Aggregate, InputHash, LabelHash, LabelTag, SharedSecret, SilentPaymentOutput,
};

struct Key {
    scan_key: SecretKey,
    spend_key: PublicKey,
    labels: Vec<Scalar>,
    change_label: Scalar,
}

// impl Keys {
//     pub fn add_key(
//         &mut self,
//         scan_key: SecretKey,
//         spend_key: PublicKey,
//         labels: Vec<Scalar>,
//     ) -> &mut Self {
//         self.0.push(Key {
//             scan_key,
//             spend_key,
//             labels,
//         });
//         self
//     }
// }

pub struct Receive {
    keys: Vec<Key>,
}

impl Receive {
    pub fn new(scan_key: SecretKey, spend_key: PublicKey, labels: Vec<u32>) -> Self {
        // TODO: Move out
        let labels = labels
            .into_iter()
            .map(|m| {
                let mut engine = LabelTag::engine();
                engine.input(&scan_key.secret_bytes());
                engine.input(&m.to_be_bytes());
                Scalar::from_be_bytes(LabelHash::from_engine(engine).to_byte_array()).unwrap()
            })
            .collect();
        let change_label = {
            let mut engine = LabelTag::engine();
            engine.input(&scan_key.secret_bytes());
            engine.input(&0u32.to_be_bytes());
            Scalar::from_be_bytes(LabelHash::from_engine(engine).to_byte_array()).unwrap()
        };
        let key = Key {
            scan_key,
            spend_key,
            labels,
            change_label,
        };

        Self { keys: vec![key] }
    }

    pub fn addresses<C>(&self, secp: &Secp256k1<C>) -> Vec<SilentPaymentAddress>
    where
        C: Signing + Verification,
    {
        self.keys
            .iter()
            .flat_map(|key| {
                let scan_key = key.scan_key.public_key(secp);

                let mut addrs = vec![SilentPaymentAddress::new(key.spend_key, scan_key, false)];

                key.labels.iter().for_each(|l| {
                    let b_m = key.spend_key.add_exp_tweak(secp, l).unwrap();
                    addrs.push(SilentPaymentAddress::new(b_m, scan_key, false))
                });

                addrs
            })
            .collect()
    }

    pub fn new_scanner(&self) -> Scanner {
        Scanner {
            keys: &self.keys,
            outputs: Default::default(),
            input_public_key: Default::default(),
            input_hash: Default::default(),
        }
    }

    pub fn scan_transaction(
        &self,
        prevouts: &HashMap<OutPoint, TxOut>,
        tx: &Transaction,
    ) -> HashSet<SilentPaymentOutput> {
        let mut builder = self.new_scanner();
        builder.add_from_transaction(prevouts, tx);
        builder.scan()
    }
}

pub struct Scanner<'a> {
    keys: &'a [Key],
    outputs: Vec<PublicKey>,
    input_public_key: Aggregate<PublicKey>,
    input_hash: InputHash,
}

impl<'a> Scanner<'a> {
    pub fn add_output_public_key(&mut self, output: XOnlyPublicKey) -> &mut Self {
        // TODO: Does it have to push PublicKey or would XOnlyPublicKey be enough?
        self.outputs.push(output.public_key(Parity::Even));
        self
    }

    pub fn add_public_key(&mut self, public_key: &PublicKey) -> &mut Self {
        self.input_public_key.add_key(public_key);
        self.input_hash.add_input_public_key(public_key).unwrap();
        self
    }

    pub fn add_outpoint(&mut self, outpoint: &OutPoint) -> &mut Self {
        self.input_hash.add_outpoint(outpoint);
        self
    }

    pub fn add_xonly_public_key(&mut self, key: &XOnlyPublicKey) -> &mut Self {
        self.add_public_key(&key.public_key(Parity::Even))
    }

    /// Adds script of a transaction output, if eligibile, to be examined
    /// whether it is an output of a Silent Payment. Only taproot outputs are
    /// considered, other output types are ignored.
    pub fn add_output_script_pubkey(&mut self, spk: &Script) -> &mut Self {
        if spk.is_p2tr() {
            self.add_output_public_key(
                spk.as_bytes()
                    .get(2..)
                    .and_then(|b| XOnlyPublicKey::from_slice(b).ok())
                    .unwrap(),
            );
        }

        self
    }

    /// Adds a transaction output, if eligibile, to be examined whether
    /// it is an output of a Silent Payment. Only taproot outputs are
    /// considered, other output types are ignored.
    pub fn add_output(&mut self, tx_out: &TxOut) -> &mut Self {
        self.add_output_script_pubkey(&tx_out.script_pubkey)
    }

    /// Adds all necessary data from a transaction and its previous outputs.
    pub fn add_from_transaction(
        &mut self,
        prevouts: &HashMap<OutPoint, TxOut>,
        tx: &Transaction,
    ) -> &mut Self {
        for tx_out in &tx.output {
            self.add_output(tx_out);
        }

        for tx_in in &tx.input {
            self.add_outpoint(&tx_in.previous_output);

            prevouts
                .get(&tx_in.previous_output)
                .and_then(|prevout| input_public_key(&prevout.script_pubkey, tx_in))
                .iter()
                .for_each(|pk| {
                    self.add_public_key(pk);
                });
        }

        self
    }

    // TODO: return indication which key matched
    pub fn scan(self) -> HashSet<SilentPaymentOutput> {
        if let Ok(input_hash) = self.input_hash.hash() {
            let input_public_key = self.input_public_key.get().unwrap();
            self.keys
                .iter()
                .flat_map(|key| {
                    Self::matched_outputs_per_key(
                        input_hash,
                        input_public_key,
                        &self.outputs,
                        key,
                        &Secp256k1::new(),
                    )
                })
                .collect()
        } else {
            HashSet::default()
        }
    }

    fn matched_outputs_per_key(
        input_hash: Scalar,
        input_public_key: PublicKey,
        outputs: &[PublicKey],
        key: &Key,
        secp: &Secp256k1<All>,
    ) -> HashSet<SilentPaymentOutput> {
        let Key {
            scan_key,
            spend_key,
            labels,
            change_label,
        } = key;

        let shared_secret = SharedSecret::new(input_hash, input_public_key, *scan_key, secp);

        let labels = std::iter::once(change_label)
            .chain(labels.iter())
            .flat_map(|&label| {
                let label_public_key = SecretKey::from_slice(&label.to_be_bytes())
                    .unwrap()
                    .public_key(secp);
                [
                    (label_public_key, label),
                    (label_public_key.negate(secp), label),
                ]
            })
            .collect::<HashMap<_, _>>();

        outputs
            .iter()
            .fold((HashSet::new(), 0u32), |(mut acc, k), &output| {
                let (pk, tk) = shared_secret.destination_public_key(*spend_key, k, secp);

                let next_output = if output == pk {
                    Some(SilentPaymentOutput::new(output.x_only_public_key().0, tk))
                } else {
                    [output, output.negate(secp)]
                        .iter()
                        .filter_map(|x| x.combine(&pk.negate(secp)).ok())
                        .find_map(|x| labels.get_key_value(&x))
                        .and_then(|(x, label)| {
                            x.combine(&pk).ok().map(|x| {
                                SilentPaymentOutput::new_with_label(
                                    x.x_only_public_key().0,
                                    tk,
                                    label.to_be_bytes(),
                                )
                            })
                        })
                };

                if let Some(out) = next_output {
                    acc.insert(out);
                    (acc, k + 1)
                } else {
                    (acc, k)
                }
            })
            .0
    }
}
