use bitcoin::secp256k1::{Keypair, Scalar, Secp256k1, SecretKey};

use crate::{
    label::{Label, LabelIndex},
    silent_payment_signing_key,
};

pub fn signing_keypair(
    spend_key: SecretKey,
    scan_key: SecretKey,
    tweak: Scalar,
    label: Option<LabelIndex>,
) -> Keypair {
    let secp = &Secp256k1::new();

    let label = label.map(|x| Label::from_index(&scan_key, x).unwrap());

    silent_payment_signing_key(spend_key, tweak, label, secp).unwrap()
}
