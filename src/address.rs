use std::str::FromStr;

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32m, ByteIterExt, Fe32, Fe32IterExt, Hrp};
use bitcoin::secp256k1::PublicKey;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SilentPaymentAddress {
    // TODO: secp256k1 Public Key?
    spend_key: PublicKey,
    scan_key: PublicKey,
}

impl SilentPaymentAddress {
    pub fn new(spend_key: PublicKey, scan_key: PublicKey) -> Self {
        Self {
            spend_key,
            scan_key,
        }
    }

    pub fn from_bech32(bech32: CheckedHrpstring) -> Result<Self, String> {
        let _hrp = bech32.hrp(); // TODO: check; network kind?

        if let Some((Fe32::Q, fes)) = bech32.fe32_iter_with_witness_version() {
            let bytes = fes.fes_to_bytes().collect::<Vec<_>>();
            let (scan_data, spend_data) = bytes.split_at(33);

            // TODO: remove unwrap
            Ok(SilentPaymentAddress {
                spend_key: PublicKey::from_slice(spend_data).unwrap(),
                scan_key: PublicKey::from_slice(scan_data).unwrap(),
            })
        } else {
            Err("".to_string())
        }
    }

    pub fn to_bech32(&self) -> String {
        [self.scan_key.serialize(), self.spend_key.serialize()]
            .concat()
            .into_iter()
            // .copied()
            .bytes_to_fes()
            .with_checksum::<Bech32m>(&Hrp::parse("sp").unwrap())
            .with_witness_version(Fe32::Q)
            .chars()
            .collect::<String>()
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
        CheckedHrpstring::new::<Bech32m>(s)
            .map_err(|e| e.to_string())
            .and_then(Self::from_bech32)
    }
}

impl std::fmt::Display for SilentPaymentAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_bech32())
    }
}
