use std::collections::HashMap;

use bitcoin::secp256k1::{
    KeyPair, Parity, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey,
};
use bitcoin::{OutPoint, Transaction, TxOut};

use crate::{input_public_key, silent_payment_signing_key, Aggregate, InputHash, SharedSecret};

#[derive(Default)]
pub struct Spend {
    input_public_key: Aggregate<PublicKey>,
    input_hash: InputHash,
}

impl Spend {
    pub fn new() -> Self {
        Self {
            input_public_key: Default::default(),
            input_hash: Default::default(),
        }
    }

    pub fn from_transaction(prevouts: &HashMap<OutPoint, TxOut>, tx: &Transaction) -> Self {
        let mut spend = Self::new();
        spend.add_from_transaction(prevouts, tx);
        spend
    }

    pub fn add_from_transaction(
        &mut self,
        prevouts: &HashMap<OutPoint, TxOut>,
        tx: &Transaction,
    ) -> &mut Self {
        tx.input.iter().for_each(|i| {
            self.add_outpoint(&i.previous_output);
            if let Some(prev) = prevouts.get(&i.previous_output) {
                if let Some(pk) = input_public_key(&prev.script_pubkey, i) {
                    self.add_public_key(&pk);
                }
            }
        });
        self
    }

    pub fn add_xonly_public_key(&mut self, key: &XOnlyPublicKey) -> &mut Self {
        self.add_public_key(&key.public_key(Parity::Even))
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

    pub fn signing_keypair(
        self,
        scan_key: SecretKey,
        spend_key: SecretKey,
        k: u32,
        label: Option<[u8; 32]>,
    ) -> KeyPair {
        let secp = &Secp256k1::new();

        let input_hash = self.input_hash.hash().unwrap();
        let input_public_key = self.input_public_key.get().unwrap();

        let shared_secret = SharedSecret::new(input_hash, input_public_key, scan_key, secp);
        let (_, tweak) = shared_secret.destination_public_key(spend_key.public_key(secp), k, secp);

        let label = Scalar::from_be_bytes(label.unwrap_or([0; 32])).unwrap();

        silent_payment_signing_key(spend_key, &crate::TweakData { tweak, label }, secp).unwrap()
    }
}
