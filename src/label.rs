use bitcoin::hashes::{sha256t::Tag, Hash, HashEngine};
use bitcoin::secp256k1::scalar::OutOfRangeError;
use bitcoin::secp256k1::{Scalar, SecretKey};

use crate::{LabelHash, LabelTag};

pub struct Label(Scalar);

impl Label {
    pub fn from_index(scan_key: &SecretKey, m: u32) -> Result<Label, OutOfRangeError> {
        let mut engine = LabelTag::engine();
        engine.input(&scan_key.secret_bytes());
        engine.input(&m.to_be_bytes());
        Scalar::from_be_bytes(LabelHash::from_engine(engine).to_byte_array()).map(Label)
    }
}
