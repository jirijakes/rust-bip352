use bitcoin::hashes::{sha256t::Tag, Hash, HashEngine};
use bitcoin::secp256k1;
use bitcoin::secp256k1::scalar::OutOfRangeError;
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey, Verification};

use crate::{LabelHash, LabelTag};

/// Index <i>m</i> of a label, guaranteed to be greater than 0 (which is reserved
/// for change).
pub struct LabelIndex(u32);

impl TryFrom<u32> for LabelIndex {
    type Error = LabelZeroError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value == CHANGE_LABEL_INDEX {
            Err(LabelZeroError)
        } else {
            Ok(Self(value))
        }
    }
}

impl Into<u32> for LabelIndex {
    fn into(self) -> u32 {
        self.0
    }
}

/// Error caused by attempting to use 0 as label (which is reserved for change).
pub struct LabelZeroError;

/// Label used to differentiate various purposes of Silent Payment address,
/// generated for a particular scan key (i. e. it is valid only for that
/// scan key for which it was derived).
pub struct Label {
    tweak: Scalar,
    index: LabelIndex,
}

impl Label {
    /// Applies label to public spend key.
    pub fn apply_to_key<C: Verification>(
        &self,
        spend_key: &PublicKey,
        secp: &Secp256k1<C>,
    ) -> Result<PublicKey, secp256k1::Error> {
        spend_key.add_exp_tweak(secp, &self.tweak)
    }
}

/// Label used for change. This label is never given to others.
pub struct ChangeLabel(Scalar);

/// Reserved label for change.
const CHANGE_LABEL_INDEX: u32 = 0;

impl Label {
    /// Creates label for secret scan key and index.
    pub fn from_index(scan_key: &SecretKey, index: LabelIndex) -> Result<Label, OutOfRangeError> {
        Self::label_tweak(scan_key, index.into()).map(|tweak| Label { tweak, index })
    }

    /// Creates label for change.
    pub fn change(scan_key: &SecretKey) -> Result<ChangeLabel, OutOfRangeError> {
        Self::label_tweak(scan_key, CHANGE_LABEL_INDEX).map(ChangeLabel)
    }

    /// Calculates tweak of the given label <i>m</i>  using
    /// <i>hash<sub>BIP0352/Label</sub>(ser<sub>256</sub>(b<sub>scan</sub>) || ser<sub>32</sub>(m))·G</i>
    /// for secret key <i>b<sub>scan</sub></i>. The result can be then added to public <i>B<sub>scan</sub></i>
    /// to form <i>B<sub>m</sub></i>, the spending part of Silent Payment address.
    fn label_tweak(b_scan: &SecretKey, m: u32) -> Result<Scalar, OutOfRangeError> {
        let mut engine = LabelTag::engine();
        engine.input(&b_scan.secret_bytes());
        engine.input(&m.to_be_bytes());
        Scalar::from_be_bytes(LabelHash::from_engine(engine).to_byte_array())
    }
}