use bitcoin::secp256k1::{Error as SecpError, Keypair, Scalar, Secp256k1, SecretKey};

use crate::label::{Label, LabelTweak};

pub fn signing_keypair(
    spend_key: SecretKey,
    scan_key: SecretKey,
    tweak: Scalar,
    label: Option<Label>,
) -> Result<Keypair, SecpError> {
    let secp = &Secp256k1::new();

    let label = label.map(|x| match x {
        Label::Change => LabelTweak::change(&scan_key).unwrap().to_scalar(),
        Label::Index(i) => LabelTweak::from_index(&scan_key, i).unwrap().to_scalar(),
    });

    let d = match label {
        None => spend_key.add_tweak(&tweak)?,
        Some(label) => spend_key.add_tweak(&tweak)?.add_tweak(&label)?,
    };

    Ok(Keypair::from_secret_key(secp, &d))
}
