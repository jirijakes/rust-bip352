use bitcoin::secp256k1::{Error as SecpError, Keypair, Scalar, Secp256k1, SecretKey};

use crate::label::Label;

pub fn signing_keypair(
    spend_key: SecretKey,
    scan_key: SecretKey,
    tweak: Scalar,
    label: Option<Label>,
) -> Result<Keypair, SecpError> {
    let secp = &Secp256k1::new();

    let signing_key = if let Some(label) = label {
        let label_tweak = label.tweak(&scan_key).unwrap().to_scalar();
        spend_key.add_tweak(&tweak)?.add_tweak(&label_tweak)?
    } else {
        spend_key.add_tweak(&tweak)?
    };

    Ok(Keypair::from_secret_key(secp, &signing_key))
}
