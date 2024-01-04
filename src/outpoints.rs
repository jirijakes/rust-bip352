use bitcoin::{
    consensus::Encodable,
    hashes::{sha256, Hash},
    secp256k1::Scalar,
    OutPoint,
};

#[derive(Default)]
pub struct OutPoints {
    outpoints: Vec<OutPoint>,
}

impl OutPoints {
    pub fn add(&mut self, outpoint: OutPoint) -> &mut OutPoints {
        // keep the outpoints ordered
        let index = self.outpoints.partition_point(|&p| p < outpoint);
        self.outpoints.insert(index, outpoint);
        self
    }

    pub fn hash(&self) -> Scalar {
        let mut engine = sha256::Hash::engine();
        self.outpoints.iter().for_each(|o| {
            o.consensus_encode(&mut engine).unwrap();
        });
        Scalar::from_be_bytes(sha256::Hash::from_engine(engine).to_byte_array()).unwrap()
    }
}
