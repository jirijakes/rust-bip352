use bitcoin::secp256k1::{
    KeyPair, Parity, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey,
};
use bitcoin::OutPoint;

use crate::{silent_payment_signing_key, Aggregate, InputNonce, SharedSecret};

pub struct Spend {
    input_public_key: Aggregate<PublicKey>,
    input_nonce: InputNonce,
}

impl Spend {
    pub fn new() -> Self {
        Self {
            input_public_key: Default::default(),
            input_nonce: Default::default(),
        }
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

    pub fn signing_keypair(
        self,
        scan_key: SecretKey,
        spend_key: SecretKey,
        k: u32,
        label: Option<[u8; 32]>,
    ) -> KeyPair {
        let secp = &Secp256k1::new();

        let input_nonce = self.input_nonce.hash().unwrap();
        let input_public_key = self.input_public_key.get().unwrap();

        let shared_secret = SharedSecret::new(input_nonce, input_public_key, scan_key, secp);
        let (_, tweak) = shared_secret.destination_public_key(spend_key.public_key(secp), k, secp);

        let label = Scalar::from_be_bytes(label.unwrap_or([0; 32])).unwrap();

        silent_payment_signing_key(spend_key, &crate::TweakData { tweak, label }, secp).unwrap()
    }
}
