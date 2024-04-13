use bitcoin::secp256k1::{Error as SecpError, Keypair, Scalar, Secp256k1, SecretKey};

use crate::label::Label;

pub fn signing_keypair(
    spend_key: SecretKey,
    scan_key: SecretKey,
    tweak: Scalar,
    label: Option<Label>,
) -> Result<Keypair, SecpError> {
    let secp = &Secp256k1::new();

    let label = label.map(|x| x.tweak(&scan_key).unwrap());

    let d = match label {
        None => spend_key.add_tweak(&tweak)?,
        Some(label) => spend_key.add_tweak(&tweak)?.add_tweak(&label.to_scalar())?,
    };

    Ok(Keypair::from_secret_key(secp, &d))
}
