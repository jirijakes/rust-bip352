use std::str::FromStr;

use bitcoin::bech32::{self, Bech32m, ByteIterExt, Fe32, Fe32IterExt, Hrp};
use bitcoin::secp256k1::PublicKey;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SilentPaymentAddress {
    spend_key: PublicKey,
    scan_key: PublicKey,
}

const HRP: Hrp = Hrp::parse_unchecked("sp");

impl SilentPaymentAddress {
    pub fn new(spend_key: PublicKey, scan_key: PublicKey) -> Self {
        Self {
            spend_key,
            scan_key,
        }
    }

    pub fn from_bech32(s: &str) -> Result<Self, String> {
        match &bech32::segwit::decode(s) {
            Ok((hrp, Fe32::Q, data)) if hrp == &HRP => {
                let (scan_data, spend_data) = data.split_at(33);
                Ok(SilentPaymentAddress {
                    spend_key: PublicKey::from_slice(spend_data).unwrap(),
                    scan_key: PublicKey::from_slice(scan_data).unwrap(),
                })
            }
            Ok((hrp, v, _)) if hrp == &HRP => Err(format!("Incorrect version {}", v)),
            Ok((hrp, Fe32::Q, _)) => Err(format!("Incorrect HRP {}", hrp)),
            Ok((hrp, v, _)) => Err(format!("Incorrect HRP {} and version {}", hrp, v)),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn to_bech32(&self) -> String {
        self.scan_key
            .serialize()
            .iter()
            .chain(self.spend_key.serialize().iter())
            .copied()
            .bytes_to_fes()
            .with_checksum::<Bech32m>(&HRP)
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
}

impl FromStr for SilentPaymentAddress {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_bech32(s)
    }
}

impl std::fmt::Display for SilentPaymentAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_bech32())
    }
}
