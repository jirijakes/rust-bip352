use bitcoin::secp256k1::{Error as SecpError, Keypair, Scalar, Secp256k1};

use crate::{label::Label, ScanSecretKey, SpendSecretKey};

pub fn signing_keypair(
    spend_key: SpendSecretKey,
    scan_key: ScanSecretKey,
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

    Ok(signing_key.to_keypair(secp))
}
