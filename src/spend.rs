use bitcoin::secp256k1::{KeyPair, SecretKey};

pub struct Spend;

impl Spend {
    pub fn new(scan_key: SecretKey, spend_key: SecretKey) -> Self {
        Self
    }

    pub fn add_output(&mut self) -> &mut Self {
        self
    }

    pub fn signing_keypair(self) -> KeyPair {
        todo!()
    }
}
