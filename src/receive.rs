use std::collections::{HashMap, HashSet};

use bitcoin::secp256k1::{
    Parity, PublicKey, Scalar, Secp256k1, SecretKey, Signing, Verification, XOnlyPublicKey,
};
use bitcoin::{OutPoint, Script, Transaction, TxOut};

use crate::address::SilentPaymentAddress;
use crate::{input_public_key, Aggregate, InputNonce, SharedSecret, SilentPaymentOutput};

pub struct Scan {
    scan_key: SecretKey,
    spend_key: PublicKey,
    labels: Vec<Scalar>,
    outputs: Vec<PublicKey>,
    input_public_key: Aggregate<PublicKey>,
    input_nonce: InputNonce,
}

impl Scan {
    pub fn new(scan_key: SecretKey, spend_key: PublicKey, labels: Vec<[u8; 32]>) -> Self {
        Self {
            scan_key,
            spend_key,
            labels: labels
                .into_iter()
                .map(|x| Scalar::from_be_bytes(x).unwrap())
                .collect(),
            outputs: Default::default(),
            input_nonce: Default::default(),
            input_public_key: Default::default(),
        }
    }

    pub fn addresses<C>(&self, secp: &Secp256k1<C>) -> Vec<SilentPaymentAddress>
    where
        C: Signing + Verification,
    {
        let scan_key = self.scan_key.public_key(secp);

        let mut addrs = vec![SilentPaymentAddress::new(self.spend_key, scan_key)];

        self.labels.iter().for_each(|l| {
            let b_m = self.spend_key.add_exp_tweak(secp, l).unwrap();
            addrs.push(SilentPaymentAddress::new(b_m, scan_key))
        });

        addrs
    }

    pub fn add_xonly_public_key(&mut self, key: &XOnlyPublicKey) -> &mut Self {
        self.add_public_key(&key.public_key(Parity::Even))
    }

    pub fn add_public_key(&mut self, public_key: &PublicKey) -> &mut Self {
        self.input_public_key.add_key(public_key);
        self.input_nonce.add_input_public_key(public_key).unwrap();
        self
    }

    pub fn add_outpoint(&mut self, outpoint: &OutPoint) -> &mut Self {
        self.input_nonce.add_outpoint(outpoint);
        self
    }

    /// Scans transaction and its previous outputs for Silent Payment outputs.
    pub fn scan_from_transaction(
        self,
        prevouts: &HashMap<OutPoint, TxOut>,
        tx: &Transaction,
    ) -> HashSet<SilentPaymentOutput> {
        let mut scan = self;
        scan.add_from_transaction(prevouts, tx);
        scan.xxx()
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

    /// Adds a transaction output, if eligibile, to be examined whether
    /// it is an output of a Silent Payment. Only taproot outputs are
    /// considered, other output types are ignored.
    pub fn add_output(&mut self, tx_out: &TxOut) -> &mut Self {
        self.add_output_script_pubkey(&tx_out.script_pubkey)
    }

    /// Adds script of a transaction output, if eligibile, to be examined
    /// whether it is an output of a Silent Payment. Only taproot outputs are
    /// considered, other output types are ignored.
    pub fn add_output_script_pubkey(&mut self, spk: &Script) -> &mut Self {
        if spk.is_v1_p2tr() {
            self.add_output_public_key(
                spk.as_bytes()
                    .get(2..)
                    .and_then(|b| XOnlyPublicKey::from_slice(b).ok())
                    .unwrap(),
            );
        }

        self
    }

    /// Unconditionally adds a public key of a transaction output to be be examined
    /// whether it is an output of a Silent Payment. Only taproot outputs are eligible.
    /// If unsure, use [`add_script_pubkey`] or [`add_tx_out`].
    pub fn add_output_public_key(&mut self, output: XOnlyPublicKey) -> &mut Self {
        // TODO: Does it have to push PublicKey or would XOnlyPublicKey be enough?
        self.outputs.push(output.public_key(Parity::Even));
        self
    }

    pub fn xxx(self) -> HashSet<SilentPaymentOutput> {
        let secp = &Secp256k1::new();

        let shared_secret = SharedSecret::new(
            self.input_nonce.hash().unwrap(),
            self.input_public_key.get().unwrap(),
            self.scan_key,
            secp,
        );

        let labels = self
            .labels
            .iter()
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

        self.outputs
            .iter()
            .fold((HashSet::new(), 0u32), |(mut acc, k), &output| {
                let (pk, _) = shared_secret.destination_public_key(self.spend_key, k, secp);

                let next_output = if output == pk {
                    Some(SilentPaymentOutput::new(output.x_only_public_key().0, k))
                } else {
                    [output, output.negate(secp)]
                        .iter()
                        .filter_map(|x| x.combine(&pk.negate(secp)).ok())
                        .find_map(|x| labels.get_key_value(&x))
                        .and_then(|(x, label)| {
                            x.combine(&pk).ok().map(|x| {
                                SilentPaymentOutput::new_with_label(
                                    x.x_only_public_key().0,
                                    k,
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
