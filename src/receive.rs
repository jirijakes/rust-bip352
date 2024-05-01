use std::collections::{HashMap, HashSet};

use bitcoin::secp256k1::scalar::OutOfRangeError;
use bitcoin::secp256k1::{All, Parity, PublicKey, Scalar, Secp256k1, XOnlyPublicKey};
use bitcoin::{OutPoint, Script, Transaction, TxIn, TxOut};

use crate::address::SilentPaymentAddress;
use crate::label::{Label, LabelIndex, LabelTweak};
use crate::{
    input_public_key, Aggregate, InputHash, ScanSecretKey, SharedSecret, SilentPaymentOutput,
    SpendPublicKey,
};

struct Key {
    scan_key: ScanSecretKey,
    spend_key: SpendPublicKey,
    labels: Vec<LabelTweak>,
    change_label: LabelTweak,
}

pub struct Receive {
    keys: Vec<Key>,
    secp: Secp256k1<All>,
}

/// # Higher-level operations
impl Receive {
    pub fn new(
        scan_key: ScanSecretKey,
        spend_key: SpendPublicKey,
        labels: Vec<LabelIndex>,
    ) -> Self {
        let labels: Result<Vec<LabelTweak>, OutOfRangeError> = labels
            .into_iter()
            .map(|m| LabelTweak::from_index(&scan_key, m))
            .collect();
        let change_label = LabelTweak::change(&scan_key).unwrap();
        let key = Key {
            scan_key,
            spend_key,
            labels: labels.unwrap(),
            change_label,
        };

        Self {
            keys: vec![key],
            secp: Secp256k1::new(),
        }
    }

    /// Returns all non-change Silent Payment addresses associated with this object.
    pub fn addresses(&self) -> Vec<SilentPaymentAddress> {
        self.keys
            .iter()
            .flat_map(|key| {
                let scan_key = key.scan_key.public_key(&self.secp);

                let mut addrs = vec![SilentPaymentAddress::new(key.spend_key, scan_key)];

                key.labels.iter().for_each(|label| {
                    let b_m = label.apply_to_key(&key.spend_key, &self.secp).unwrap();
                    addrs.push(SilentPaymentAddress::new(b_m, scan_key))
                });

                addrs
            })
            .collect()
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

/// # Lower-level operations
impl Receive {
    pub fn new_scanner(&self) -> Scanner {
        Scanner {
            keys: &self.keys,
            outputs: Default::default(),
            input_public_key: Default::default(),
            input_hash: Default::default(),
            secp: &self.secp,
        }
    }
}

pub struct Scanner<'a> {
    keys: &'a [Key],
    outputs: Vec<PublicKey>,
    input_public_key: Aggregate<PublicKey>,
    input_hash: InputHash,
    secp: &'a Secp256k1<All>,
}

/// # High-level operations
///
/// _Methods in this section provide high-level access to scanning. They should not be mixed with other levels._
impl<'a> Scanner<'a> {
    /// Adds all necessary data from a transaction and its previous outputs.
    pub fn add_from_transaction(
        &mut self,
        prevouts: &HashMap<OutPoint, TxOut>,
        tx: &Transaction,
    ) -> &mut Self {
        for tx_in in &tx.input {
            // TODO: blow up if a prevout is missing; we require them all
            if let Some(prev) = prevouts.get(&tx_in.previous_output) {
                self.add_input(&prev.script_pubkey, tx_in);
            };
        }

        for tx_out in &tx.output {
            self.add_output(tx_out);
        }

        self
    }
}

/// # Mid-level operations
///
/// _Methods in this section provide middle-level access to scanning. They should not be mixed with other levels._
impl<'a> Scanner<'a> {
    /// Ads an input if it is eligible. Script pubkey of previous output has to be
    /// provided, too.
    pub fn add_input(&mut self, previous_script_pubkey: &Script, input: &TxIn) -> &mut Self {
        self.add_input_outpoint(&input.previous_output);
        if let Some(pk) = input_public_key(previous_script_pubkey, input) {
            self.add_input_public_key(&pk);
        };

        self
    }

    /// Adds a transaction output, if eligibile, to be examined whether
    /// it is an output of a Silent Payment. Only taproot outputs are
    /// considered, other output types are ignored.
    pub fn add_output(&mut self, tx_out: &TxOut) -> &mut Self {
        self.add_output_script_pubkey(&tx_out.script_pubkey)
    }
}

/// # Low-level operations
///
/// _Methods in this section provide low-level access to scanning. They should not be mixed with other levels._
impl<'a> Scanner<'a> {
    pub fn add_input_outpoint(&mut self, outpoint: &OutPoint) -> &mut Self {
        self.input_hash.add_outpoint(outpoint);
        self
    }

    /// Unconditionally adds a public key from an input.
    ///
    /// TODO: Explain dangers
    pub fn add_input_public_key(&mut self, public_key: &PublicKey) -> &mut Self {
        self.input_public_key.add_key(public_key);
        self.input_hash.add_input_public_key(public_key).unwrap();
        self
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

    pub fn add_output_public_key(&mut self, output: XOnlyPublicKey) -> &mut Self {
        // TODO: Does it have to push PublicKey or would XOnlyPublicKey be enough?
        self.outputs.push(output.public_key(Parity::Even));
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
                        self.secp,
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

        let mut labels = labels
            .iter()
            .flat_map(|label| {
                let label_public_key = label.to_public_key(secp);
                [
                    (label_public_key, label.label()),
                    (label_public_key.negate(secp), label.label()),
                ]
            })
            .collect::<HashMap<_, _>>();

        labels.insert(change_label.to_public_key(secp), Label::Change);

        let shared_secret =
            SharedSecret::new(input_hash, input_public_key, scan_key.to_secret_key(), secp)
                .unwrap();

        let mut outputs: HashSet<PublicKey> = outputs.iter().copied().collect();

        let mut xxx: HashSet<SilentPaymentOutput> = Default::default();

        let mut k = 0u32;

        let (pk, tk) = shared_secret.destination_public_key(*spend_key, k, secp);

        let z = if let Some(x) = outputs.get(&pk) {
            xxx.insert(SilentPaymentOutput::new(x.x_only_public_key().0, tk));
            k += 1;
            Some(*x)
        } else if let Some((a, b)) = outputs.iter().find_map(|output| {
            [output, &output.negate(secp)]
                .iter()
                .filter_map(|output| output.combine(&pk.negate(secp)).ok())
                .find_map(|x| labels.get_key_value(&x))
                .and_then(|(x, label)| {
                    x.combine(&pk).ok().map(|x| {
                        let spo = SilentPaymentOutput::new_with_label(
                            x.x_only_public_key().0,
                            tk,
                            *label,
                        );
                        (spo, output)
                    })
                })
        }) {
            xxx.insert(a);
            k += 1;
            Some(*b)
        } else {
            None
        };

        if let Some(z) = z {
            outputs.remove(&z);
        }

        xxx
    }
}
