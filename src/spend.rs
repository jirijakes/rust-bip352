use bitcoin::secp256k1::{Error as SecpError, Keypair, Scalar, Secp256k1, SecretKey};

use crate::label::{Label, XxxLabel};

pub fn signing_keypair(
    spend_key: SecretKey,
    scan_key: SecretKey,
    tweak: Scalar,
    label: Option<XxxLabel>,
) -> Result<Keypair, SecpError> {
    let secp = &Secp256k1::new();

    let label = label.map(|x| match x {
        XxxLabel::Change => Label::change(&scan_key).unwrap().to_scalar(),
        XxxLabel::Index(i) => Label::from_index(&scan_key, i).unwrap().to_scalar(),
    });

    let d = match label {
        None => spend_key.add_tweak(&tweak)?,
        Some(label) => spend_key.add_tweak(&tweak)?.add_tweak(&label)?,
    };

    Ok(Keypair::from_secret_key(secp, &d))
}
