use bitcoin::hashes::{sha256t::Tag, Hash, HashEngine};
use bitcoin::secp256k1;
use bitcoin::secp256k1::scalar::OutOfRangeError;
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey, Signing, Verification};

use crate::{LabelHash, LabelTag};

/// Reserved label for change.
const CHANGE_LABEL_INDEX: u32 = 0;

#[derive(Copy, Clone, Hash, Debug, Ord, PartialEq, PartialOrd, Eq)]
pub enum Label {
    Change,
    Index(LabelIndex),
}

impl Label {
    /// Tweak label with a secret scan key.
    pub fn tweak(&self, scan_key: &SecretKey) -> Result<LabelTweak, OutOfRangeError> {
        match self {
            Label::Change => LabelTweak::change(scan_key),
            Label::Index(i) => LabelTweak::from_index(scan_key, *i),
        }
    }
}

/// Index <i>m</i> of a label, guaranteed to be greater than 0 (which is reserved
/// for change).
#[derive(Copy, Clone, Debug, Hash, Ord, PartialEq, PartialOrd, Eq)]
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

impl TryFrom<&u32> for LabelIndex {
    type Error = LabelZeroError;

    fn try_from(value: &u32) -> Result<Self, Self::Error> {
        if *value == CHANGE_LABEL_INDEX {
            Err(LabelZeroError)
        } else {
            Ok(Self(*value))
        }
    }
}

impl From<LabelIndex> for u32 {
    fn from(val: LabelIndex) -> Self {
        val.0
    }
}

/// Error caused by attempting to use 0 as label (which is reserved for change).
#[derive(Debug)]
pub struct LabelZeroError;

/// Label used to differentiate various purposes of Silent Payment address,
/// generated for a particular scan key (i. e. it is valid only for that
/// scan key for which it was derived).
pub struct LabelTweak {
    tweak: Scalar,
    label: Label,
}

impl LabelTweak {
    /// Creates label for secret scan key and index.
    pub fn from_index(
        scan_key: &SecretKey,
        index: LabelIndex,
    ) -> Result<LabelTweak, OutOfRangeError> {
        Self::label_tweak(scan_key, index.into()).map(|tweak| LabelTweak {
            tweak,
            label: Label::Index(index),
        })
    }

    /// Creates label for change.
    pub fn change(scan_key: &SecretKey) -> Result<LabelTweak, OutOfRangeError> {
        Self::label_tweak(scan_key, CHANGE_LABEL_INDEX).map(|tweak| LabelTweak {
            tweak,
            label: Label::Change,
        })
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

    /// Applies label to public spend key.
    pub fn apply_to_key<C: Verification>(
        &self,
        spend_key: &PublicKey,
        secp: &Secp256k1<C>,
    ) -> Result<PublicKey, secp256k1::Error> {
        spend_key.add_exp_tweak(secp, &self.tweak)
    }

    pub fn to_public_key<C: Signing>(&self, secp: &Secp256k1<C>) -> PublicKey {
        SecretKey::from_slice(&self.tweak.to_be_bytes())
            .expect("tweak is on curve, so should be the secret key")
            .public_key(secp)
    }

    pub(crate) fn to_scalar(&self) -> Scalar {
        self.tweak
    }

    pub fn label(&self) -> Label {
        self.label
    }
}
