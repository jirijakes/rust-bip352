use std::str::FromStr;

use bech32::primitives::decode::UncheckedHrpstring;
use bech32::{Bech32m, ByteIterExt, Fe32, Fe32IterExt, Hrp};
use bitcoin::secp256k1::PublicKey;

/// Human-readable part for encoded address on mainnet.
const HRP: Hrp = Hrp::parse_unchecked("sp");

/// Human-readable part for encoded address on testing networks (signet, testnet etc.).
const THRP: Hrp = Hrp::parse_unchecked("tsp");

/// Decoded Silent Payment address.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SilentPaymentAddress {
    spend_key: PublicKey,
    scan_key: PublicKey,
    testing: bool,
}

impl SilentPaymentAddress {
    pub fn new(spend_key: PublicKey, scan_key: PublicKey, testing: bool) -> Self {
        Self {
            spend_key,
            scan_key,
            testing,
        }
    }

    pub fn new_mainnet(spend_key: PublicKey, scan_key: PublicKey) -> Self {
        Self {
            spend_key,
            scan_key,
            testing: false,
        }
    }

    pub fn new_testing(spend_key: PublicKey, scan_key: PublicKey) -> Self {
        Self {
            spend_key,
            scan_key,
            testing: true,
        }
    }

    pub fn from_bech32(s: &str) -> Result<Self, DecodeError> {
        let ch = UncheckedHrpstring::new(s).map_err(|_| DecodeError::InvalidHrp)?;

        let testing = if ch.hrp() == HRP {
            false
        } else if ch.hrp() == THRP {
            true
        } else {
            Err(DecodeError::UnknownHrp(ch.hrp().to_string()))?
        };

        ch.validate_checksum::<Bech32m>()
            .map_err(|_| DecodeError::InvalidChecksum)?;

        let mut c = ch.remove_checksum::<Bech32m>();

        let data: Vec<u8> = match c.remove_witness_version() {
            Some(Fe32::L) => Err(DecodeError::Version)?,
            Some(Fe32::Q) => c.byte_iter().collect(),
            Some(_) => c.byte_iter().take(66).collect(),
            None => Err(DecodeError::Version)?,
        };

        if data.len() == 66 {
            let (scan_data, spend_data) = data.split_at(33);
            Ok(SilentPaymentAddress {
                spend_key: PublicKey::from_slice(spend_data).unwrap(),
                scan_key: PublicKey::from_slice(scan_data).unwrap(),
                testing,
            })
        } else {
            Err(DecodeError::InvalidLength(data.len(), 66))?
        }
    }

    pub fn to_bech32(&self) -> String {
        let hrp = if self.is_testing() { THRP } else { HRP };
        self.scan_key
            .serialize()
            .iter()
            .chain(self.spend_key.serialize().iter())
            .copied()
            .bytes_to_fes()
            .with_checksum::<Bech32m>(&hrp)
            .with_witness_version(Fe32::Q)
            .chars()
            .collect()
    }

    pub fn spend_key(&self) -> PublicKey {
        self.spend_key
    }

    pub fn scan_key(&self) -> PublicKey {
        self.scan_key
    }

    pub fn is_testing(&self) -> bool {
        self.testing
    }
}

impl FromStr for SilentPaymentAddress {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_bech32(s)
    }
}

impl std::fmt::Display for SilentPaymentAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_bech32())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    UnknownHrp(String),
    InvalidHrp,
    InvalidChecksum,
    Version,
    InvalidLength(usize, usize),
}

#[cfg(test)]
mod tests {
    use bech32::{Bech32m, ByteIterExt, Fe32, Fe32IterExt, Hrp};
    use bitcoin::secp256k1::{PublicKey, SecretKey};
    use proptest::prelude::*;
    use rand::rngs::OsRng;
    use secp256k1::Secp256k1;

    use super::{DecodeError, SilentPaymentAddress, HRP, THRP};

    fn secret_key() -> impl Strategy<Value = SecretKey> {
        Just(SecretKey::new(&mut OsRng))
    }

    fn public_key() -> impl Strategy<Value = PublicKey> {
        secret_key().prop_map(|sec| sec.public_key(&Secp256k1::new()))
    }

    fn make_address<'a>(data: impl Iterator<Item = &'a u8>, hrp: &Hrp, version: Fe32) -> String {
        data.copied()
            .bytes_to_fes()
            .with_checksum::<Bech32m>(hrp)
            .with_witness_version(version)
            .chars()
            .collect()
    }

    #[rustfmt::skip]
    prop_compose! {
	fn silent_payment_address_v0()(
            pk1 in public_key(),
            pk2 in public_key(),
            hrp in prop_oneof!(Just(HRP), Just(THRP))
	) -> String {
	    make_address(
		pk1.serialize().iter().chain(pk2.serialize().iter()),
		&hrp,
		Fe32::Q
	    )
	}
    }

    #[rustfmt::skip]
    prop_compose! {
	fn silent_payment_address_v0_long()(
            pk1 in public_key(),
            pk2 in public_key(),
	    appendix in prop::collection::vec(prop::num::u8::ANY, 1..10),
            hrp in prop_oneof!(Just(HRP), Just(THRP))
	) -> String {
	    make_address(
		pk1.serialize().iter().chain(pk2.serialize().iter()).chain(appendix.iter()),
		&hrp,
		Fe32::Q
	    )
	}
    }

    #[rustfmt::skip]
    prop_compose! {
	fn silent_payment_address_vx()(
            pk1 in public_key(),
            pk2 in public_key(),
	    appendix in prop::collection::vec(prop::num::u8::ANY, 0..100),
            hrp in prop_oneof![Just(HRP), Just(THRP)],
	    version in prop_oneof![
		Just(Fe32::P), Just(Fe32::Z), Just(Fe32::R), Just(Fe32::Y), Just(Fe32::_9), Just(Fe32::X),
		Just(Fe32::_8), Just(Fe32::G), Just(Fe32::F), Just(Fe32::_2), Just(Fe32::T), Just(Fe32::V),
		Just(Fe32::D), Just(Fe32::W), Just(Fe32::_0) , Just(Fe32::S) /*, Just(Fe32::_3), Just(Fe32::J),
		Just(Fe32::N), Just(Fe32::_5), Just(Fe32::_4), Just(Fe32::K), Just(Fe32::H), Just(Fe32::C),
		Just(Fe32::E), Just(Fe32::_6), Just(Fe32::M), Just(Fe32::U), Just(Fe32::A), Just(Fe32::_7),*/
	    ]
	) -> String {
	    make_address(
		pk1.serialize().iter().chain(pk2.serialize().iter()).chain(appendix.iter()),
		&hrp,
		version
	    )
	}
    }

    #[rustfmt::skip]
    prop_compose! {
	fn silent_payment_address_v31()(
            data in prop::collection::vec(prop::num::u8::ANY, 0..500),
            hrp in prop_oneof!(Just(HRP), Just(THRP))
	) -> String {
	    make_address(data.iter(), &hrp, Fe32::L)
	}
    }

    #[rustfmt::skip]
    proptest! {
	#[test]
	fn parse_valid_address_v0(s in silent_payment_address_v0()) {
	    let addr = SilentPaymentAddress::from_bech32(&s);
            prop_assert!(addr.is_ok());
	    if let Ok(addr) = addr {
		prop_assert_eq!(addr.is_testing(), s.starts_with("tsp"));
	    }
	}

	#[test]
	fn parse_valid_address_vx(s in silent_payment_address_vx()) {
	    let addr = SilentPaymentAddress::from_bech32(&s);
            prop_assert!(addr.is_ok());
	    if let Ok(addr) = addr {
		prop_assert_eq!(addr.is_testing(), s.starts_with("tsp"));
	    }
	}

	#[test]
	fn parse_invalid_address_v31(s in silent_payment_address_v31()) {
            prop_assert_eq!(SilentPaymentAddress::from_bech32(&s), Err(DecodeError::Version));
	}

	#[test]
	fn parse_invalid_address_v0(s in silent_payment_address_v0_long()) {
            prop_assert!(matches!(SilentPaymentAddress::from_bech32(&s), Err(DecodeError::InvalidLength(_, 66))));
	}
    }
}
