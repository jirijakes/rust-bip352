use std::str::FromStr;

use bech32::{FromBase32, ToBase32};
use bitcoin::secp256k1::PublicKey;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SilentPaymentAddress {
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

    pub fn from_bech32(s: &str) -> Result<Self, String> {
        let (_hrp, bytes, _var) = bech32::decode(s).unwrap();

        if let Some((version, data)) = bytes.split_first() {
            if version.to_u8() == 0 {
                let bytes = Vec::from_base32(data).unwrap();
                let (scan_data, spend_data) = bytes.split_at(33);
                Ok(SilentPaymentAddress {
                    spend_key: PublicKey::from_slice(spend_data).unwrap(),
                    scan_key: PublicKey::from_slice(scan_data).unwrap(),
                })
            } else {
                Err("".to_string())
            }
        } else {
            Err("".to_string())
        }
    }

    pub fn to_bech32(&self) -> String {
        let version = bech32::u5::try_from_u8(0).expect("no problems");
        let mut data = vec![version];

        data.append(
            &mut [self.scan_key.serialize(), self.spend_key.serialize()]
                .concat()
                .to_base32(),
        );

        bech32::encode("sp", data, bech32::Variant::Bech32m).unwrap()
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
