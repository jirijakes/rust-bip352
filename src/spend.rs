use bitcoin::secp256k1::{Keypair, Scalar, Secp256k1, SecretKey};

use crate::silent_payment_signing_key;

pub fn signing_keypair(spend_key: SecretKey, tweak: Scalar, label: Option<[u8; 32]>) -> Keypair {
    let secp = &Secp256k1::new();

    let label = Scalar::from_be_bytes(label.unwrap_or([0; 32])).unwrap();

    silent_payment_signing_key(spend_key, &crate::TweakData { tweak, label }, secp).unwrap()
}
