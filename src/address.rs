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

#[derive(Debug)]
pub enum DecodeError {
    UnknownHrp(String),
    InvalidHrp,
    InvalidChecksum,
    Version,
    InvalidLength(usize, usize),
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::SilentPaymentAddress;

    #[test]
    fn parse() {
        [
	    "sp1qqgrz6j0lcqnc04vxccydl0kpsj4frfje0ktmgcl2t346hkw30226xqupawdf48k8882j0strrvcmgg2kdawz53a54dd376ngdhak364hzcmynqtn",
	    "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgq7c2zfthc6x3a5yecwc52nxa0kfd20xuz08zyrjpfw4l2j257yq6qgnkdh5",
	    "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqaxww2fnhrx05cghth75n0qcj59e3e2anscr0q9wyknjxtxycg07y3pevyj",
	    "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjex54dmqmmv6rw353tsuqhs99ydvadxzrsy9nuvk74epvee55drs734pqq",
	    "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
	    "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjyh2ju7hd5gj57jg5r9lev3pckk4n2shtzaq34467erzzdfajfggty6aa5",
	    "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqsg59z2rppn4qlkx0yz9sdltmjv3j8zgcqadjn4ug98m3t6plujsq9qvu5n",
	    "sp1qqw6vczcfpdh5nf5y2ky99kmqae0tr30hgdfg88parz50cp80wd2wqqauj52ymtc4xdkmx3tgyhrsemg2g3303xk2gtzfy8h8ejet8fz8jcw23zua",
	    "sp1qqw6vczcfpdh5nf5y2ky99kmqae0tr30hgdfg88parz50cp80wd2wqqlv6saelkk5snl4wfutyxrchpzzwm8rjp3z6q7apna59z9huq4x754e5atr"
	]
	    .iter().for_each(|s| {
		let res = SilentPaymentAddress::from_str(s);
		assert!(res.is_ok(), "{s} : {res:?}");
	    });
    }
}
