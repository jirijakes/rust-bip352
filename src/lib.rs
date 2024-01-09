//! This library provides functions for working with sending and receiving
//! Bitcoin Silent Payments according to BIP 352 proposal.
use bitcoin::consensus::serialize;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::key::TapTweak;
use bitcoin::secp256k1::{
    Error as SecpError, KeyPair, Parity, PublicKey, Scalar, Secp256k1, SecretKey, Signing,
    Verification, XOnlyPublicKey,
};
use bitcoin::{OutPoint, Script, ScriptBuf, TxIn};

pub mod address;
#[cfg(feature = "receive")]
pub mod receive;
#[cfg(feature = "send")]
pub mod send;
pub mod spend;

#[derive(Default)]
pub struct InputNonce {
    /// Holds the least (so far) outpoint bytes.
    least_outpoint: Option<[u8; 36]>,

    // TODO: Remove when test vector updated.
    #[deprecated = "specification changed"]
    outpoints: Vec<[u8; 36]>,

    /// Holds aggregated input public key.
    public_key: Aggregate<PublicKey>,
}

impl InputNonce {
    /// Creates new, empty input nonce.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers new outpoint that is subject of calculation of the input nonce.
    pub fn add_outpoint(&mut self, outpoint: &OutPoint) -> &mut InputNonce {
        let bytes: [u8; 36] = serialize(outpoint)
            .try_into()
            .expect("outpoint serializes to 36 bytes");
        self.add_outpoint_serialized(bytes)
    }

    /// Registers new already-serialized outpoint that is subject of calculation of the input nonce.
    pub fn add_outpoint_serialized(&mut self, bytes: [u8; 36]) -> &mut InputNonce {
        match self.least_outpoint.as_ref() {
            Some(least) if least <= &bytes => {}
            _ => {
                self.least_outpoint.replace(bytes);
            }
        };

        // TODO: Removev when test vector updated.
        // keep the outpoints ordered
        let index = self.outpoints.partition_point(|&p| p < bytes);
        self.outpoints.insert(index, bytes);

        self
    }

    pub fn add_input_public_key(&mut self, public_key: &PublicKey) -> Option<&mut InputNonce> {
        self.public_key.add_key(public_key)?;
        Some(self)
    }

    /// Returns input nonce.
    pub fn hash(self) -> Result<Scalar, InputNonceError> {
        let mut engine = sha256::Hash::engine();

        // TODO: Remove when test vector updated.
        self.outpoints.iter().for_each(|o| engine.input(o));

        // TODO: Uncomment when test vector updated
        // let outpoint = self.least_outpoint.ok_or(InputNonceError::NoOutPoint)?;
        // engine.input(&outpoint);
        // let public_key = self.public_key.get().ok_or(InputNonceError::NoPublicKey)?;
        // engine.input(&public_key.serialize());

        let hash = sha256::Hash::from_engine(engine);
        Scalar::from_be_bytes(hash.to_byte_array()).map_err(|_| InputNonceError::InvalidValue)
    }
}

#[derive(Debug)]
pub enum InputNonceError {
    NoOutPoint,
    NoPublicKey,
    InvalidValue,
}

/// Marks keys, public or secret, that can be added together.
trait Key: Sized {
    /// Adds two keys together.
    ///
    /// # Errors
    ///
    /// Returns `None` if the result would not be a valid key.
    fn plus(&self, other: &Self) -> Option<Self>;
}

impl Key for PublicKey {
    fn plus(&self, other: &Self) -> Option<Self> {
        self.combine(other).ok()
    }
}

impl Key for SecretKey {
    fn plus(&self, other: &Self) -> Option<Self> {
        self.add_tweak(&(*other).into()).ok()
    }
}

/// Holds a key that is being aggregated with other keys.
struct Aggregate<K>(Option<K>);

impl<K> Aggregate<K> {
    /// Adds another key to the aggregate.
    ///
    /// # Errors
    ///
    /// Returns `None` if the new key could not be aggegated due to the result
    /// not being a valid key.
    fn add_key(&mut self, key: &K) -> Option<&mut Self>
    where
        K: Key + Clone,
    {
        match self.0.as_ref() {
            Some(agg) => {
                self.0.replace(agg.plus(key)?);
                Some(self)
            }
            None => {
                self.0.replace(key.clone());
                Some(self)
            }
        }
    }

    /// Returns result of the aggregation.
    ///
    /// # Errors
    ///
    /// Returns `None` if no key was successfully added.
    fn get(self) -> Option<K> {
        self.0
    }
}

impl<K> Default for Aggregate<K> {
    fn default() -> Self {
        Self(None)
    }
}

#[derive(Debug)]
pub struct TweakData {
    tweak: Scalar,
    label: Scalar,
}

impl TweakData {
    pub fn new(tweak: Scalar) -> Self {
        Self {
            tweak,
            label: Scalar::ZERO,
        }
    }

    pub fn new_with_label(tweak: Scalar, label: Scalar) -> Self {
        Self { tweak, label }
    }
}

#[derive(Debug)]
pub struct SharedSecret([u8; 33]);

impl SharedSecret {
    pub fn new<C: Verification>(
        outpoints_hash: Scalar,
        pk: PublicKey,
        sk: SecretKey,
        secp: &Secp256k1<C>,
    ) -> SharedSecret {
        let ecdh = sk.mul_tweak(&outpoints_hash).unwrap();
        SharedSecret(pk.mul_tweak(secp, &ecdh.into()).unwrap().serialize())
    }

    pub fn destination_output<C: Verification>(
        &self,
        spend_key: PublicKey,
        k: u32,
        secp: &Secp256k1<C>,
    ) -> ScriptBuf {
        let (p_k, _) = self.destination_public_key(spend_key, k, secp);

        ScriptBuf::new_v1_p2tr_tweaked(XOnlyPublicKey::from(p_k).dangerous_assume_tweaked())
    }

    pub fn destination_public_key<C: Verification>(
        &self,
        spend_key: PublicKey,
        k: u32,
        secp: &Secp256k1<C>,
    ) -> (PublicKey, Scalar) {
        let mut engine = sha256::Hash::engine();
        engine.input(&self.0);
        engine.input(&k.to_be_bytes());

        let t_k = Scalar::from_be_bytes(sha256::Hash::from_engine(engine).to_byte_array()).unwrap();
        let p_k = spend_key.add_exp_tweak(secp, &t_k).unwrap();

        if p_k.x_only_public_key().1 == Parity::Odd {
            (p_k.negate(secp), t_k)
        } else {
            (p_k, t_k)
        }
    }
}

/// Creates key pair used for schnorr signing.
pub fn silent_payment_signing_key<C: Signing>(
    spend_key: SecretKey,
    TweakData { tweak, label }: &TweakData,
    secp: &Secp256k1<C>,
) -> Result<KeyPair, SecpError> {
    // d = b_spend + t_k + hash(b_scan || m)
    let d = spend_key.add_tweak(tweak)?.add_tweak(label)?;
    Ok(KeyPair::from_secret_key(secp, &d))
}

/// Attempts to extract public key from an input and the output it points to. Returns
/// `None` if public key could not be extracted.
///
/// See section _Inputs For Shared Secret Derivation_ in BIP352 for details.
pub fn input_public_key(prevout: &Script, input: &TxIn) -> Option<PublicKey> {
    if prevout.is_p2pkh() {
        let ss = input.script_sig.as_bytes();
        ss.get(ss.len() - 33..)
            .and_then(|b| PublicKey::from_slice(b).ok())
    } else if prevout.is_v0_p2wpkh() {
        input
            .witness
            .nth(1)
            .and_then(|b| PublicKey::from_slice(b).ok())
    } else if prevout.is_v1_p2tr() {
        prevout
            .as_bytes()
            .get(2..)
            .and_then(|b| XOnlyPublicKey::from_slice(b).ok())
            .map(|k| k.public_key(Parity::Even))
    // } else if prevout.script_pubkey.is_p2sh() { TODO: P2SH-P2WPKH
    } else {
        prevout.p2pk_public_key().map(|pk| pk.inner)
    }
}

#[cfg(test)]
mod test {
    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::hex::FromHex;
    use bitcoin::Transaction;

    use crate::input_public_key;

    #[test]
    fn extract_pk_from_pkh() {
        let tx = bitcoin::consensus::deserialize::<Transaction>(&Vec::from_hex("01000000011856945d6a1ad35c2508c4a5f5ea66be5704db77f427a440f0ef334248e86443000000006b483045022100da9659a5697a2f98e1fa1979e090d8b1e3360cae211a9837a54068df517679f3022057d4885e3685e88ce348b5be1daeb7636aabb12a18eb561fc3a7a5306642c35c0121033586349f482008172d85d2ce5bd61995c864f8bf796c40f49bc6d5b8107df5c6ffffffff0220f661000000000017a9144acea97083d65ebacef745372786a3c3876d1d1b874ee71300000000001976a9144d0b5f8d4b1d89eddc8269bef5255017f44e003f88ac00000000").unwrap()).unwrap();

        let prev = deserialize::<Transaction>(&Vec::from_hex("0100000001510d01348d6085971a5aeb1889dccfbc9c04066991e32e6212b6b8c98f01d23e000000006a473044022074ba5477db90089a264a981ccad24b17ed9e5a44256477a291069f66b532c8d6022012dc8ee766eb1470d22305da16b7e85f546a5fe017e6b15f45b7311d8de627b201210361b7dcaff946649a6e36d35fcd9f45edbb60c39be159a4796e99bcd66373774fffffffff0207317800000000001976a914dac493c1822e2bac7bb7d1308c8b5860ee4d3b4288acfc06d9000000000017a914454d3ad7b59d29b7dbdbee91fd7b209bdd39662a8700000000").unwrap()).unwrap();

        assert!(input_public_key(&prev.output[0].script_pubkey, &tx.input[0],).is_some());
    }

    #[test]
    fn extract_pk_from_wpkh() {
        let tx = deserialize::<Transaction>(&Vec::from_hex("02000000000101269269bcac461236a1af6301f4f4bd33c2cd966d48c770a25406c4f5b3015f100000000000fdffffff02483b09000000000017a914e81d8995a7caa17a379967c37a79dc1ce80de2ea870872cb0000000000160014d0a2fc417c47010c2c0b5f192b2c6de07b1ec1e202473044022001216bd9d3ccf9f10a19df8b58a25bdde2a118f74679f7ca6e72cc9d6aceb68b022046e993d8b8a97962911e7db6f9dbb59a01e23bc63e787d16f52562cc5959e43f0121024bb3d2a761677e988221edd2a51220d325de43de4ff88409d2cf4eeb787f63e1ed8e0c00").unwrap()).unwrap();

        let prev = deserialize::<Transaction>(&Vec::from_hex("02000000000104227ebdf59aa75eb65bc3666590b3b52b474678cbafa55e227137aa6f74e1bdde0000000000ffffffff1e5cfbbde34444f49d3e7c2b12bf369cdb062e1d5c14b52050c6db444a073e260000000000ffffffff57bc82c33cefd4b97bc10ba505bc37d9d7811b95743735ec6133dcadea13095e0000000000ffffffff556c8f583ab9cd9f0a5f475c768b75e265d5bb47d60f5ed39cc9e92d1670dde40000000000ffffffff02c753d500000000001600140d281cbad529b089c548f1c062587f32df8b2b7d949a7400000000001600147da639cdbbbc2cfc8d6a06bb3dae2a9a380ee6dc024730440220289e5a66676337e1d04cebd246f4495fdeb7f5a49a04e1b2987dcb14a8b4d8d702204414c22159c1d85521539b601a36c27ff6fe4f8f04ba5cce25f8242983569feb012102eea57d7f5af2c9ca13dcb3cfa7916fd6b005f9e10b78d3691d435b41402cb7ab02473044022018edcc3e25176f60e6b2c7d31f3534196772a0a5697adcc99165257952140fa902206d239be6d38c30dc7d9a6f434ea69d25d2256d69d8205aba422836384a7579f3012102a4a8b0750cbb33b007eb4d4f1db43c772964e71e354b650ce24e6b9ae8ac0a0d02473044022063e8ea69549f3fd85893963de3b64c6d8ada62a9add0306d6530c6749c32c0c002206698636cb4dcc5b6f898f97912b3ee83df4f239ffd5204138205a50244f62d630121031f40841d74b92963eb641a17be3ad9a9e244b88556e08d09fdb50531bd9ea8ca02473044022025090f5b98ae9b421db3aca367fee452f9c18e070446c2d4b88ff6b072408ea20220369d91093ff6be68cf1ae1304b0916cf830f9400358c2d1131b80dc88a26a8c7012102fb513f05ac31baeeec03eeb36b75e2724cb471c2585b25b76d5f26ffbfebdeca00000000").unwrap()).unwrap();

        assert!(input_public_key(&prev.output[0].script_pubkey, &tx.input[0],).is_some());
    }

    #[test]
    fn extract_pk_from_tr() {
        let tx = deserialize::<Transaction>(&Vec::from_hex("020000000001011df72c869516a0c8addb12baa07eddce864d259a2455f87b3547a8117fc2196b0700000000fdffffff02cd50000000000000225120d0b9435a1c22f3d999f9af68ab510a9918ba34bf64be395ae5f605552fd5775cf16c0d0000000000225120c11979449d56f6066c0ffd622ca89213fbacc2f742653063cb120a24d7f2c1080140e6d3e4f8a3b74dea6597638411725128027fd352f260c42f44f07eaaf67aa481552b174df077ed33ffb85c48a4218bbc175b8c1a85c00647ad30fdbe222b8ee700000000").unwrap()).unwrap();

        let prev = deserialize::<Transaction>(&Vec::from_hex("02000000000103d1f0417afbbbda5c5c6564bb456afb9fea3562d5b58547670ecb37f1dcfb91070100000000fdffffff4195e92c1d973266632b34e1ea025b1a88f57e13724b7100fefab1139f0a73bb0100000000fdffffffe157c6fe95807a2984c5f5975d7a5cb7bcca2057dd3fdbcabb6b3ea7ea51121d0100000000fdffffff0b0c9d4c0000000000160014c636fe9763effbdb212c74d9f8cf1e4e5c49f5bf1cf10b000000000016001459a449d01b453a02dd8f4e571593a4647640da3277700500000000001600143273c760e037bfbb56c0e65084c840febb1dafe560ea000000000000160014ed56e3e6bd0150f442803e2aadcfcefab51b36fb60ea000000000000160014285cf327a6623d590d0766175eac6cf4eebaf418c2970a0000000000160014cfd32ca45248f758ef6476c134a47aa00323328ef3b203000000000016001420f3c4a2f1502ae4237e15676984c0f933bd38aae0570e0000000000225120c11979449d56f6066c0ffd622ca89213fbacc2f742653063cb120a24d7f2c108fc81450000000000160014ab2159e5c0d88335623d18a02e2c94d4e3d332fa724b070000000000160014200d178390e34bd6b7bb283542387a2779493cd4a54abb5d00000000160014f60834ef165253c571b11ce9fa74e46692fc5ec10247304402205dde094af4fbbfca450686f75781f826cdfcdc46ebf2a993a1a7f871f49bd00e02205d8bb8d7549de0bc9e40f8db08a4013ab711a365c41c01490149369c0b18e60e0121026e5628506ecd33242e5ceb5fdafe4d3066b5c0f159b3c05a621ef65f177ea28602483045022100986016daece841e3f9c7a34f53bc12771dcc8a3c439b574c72bdc6568493570602205842ff775464a4966b11c65738662fa579098ad3aa8421fffa01243780386dbc0121026e5628506ecd33242e5ceb5fdafe4d3066b5c0f159b3c05a621ef65f177ea28602473044022017c3e474666b02b38fb7bffd7cb856e2c3332834fd9d1906757164175e85b6ce022005f04e95c380e005ad8c1d101ccb28d7714aa0bdc23e40dc7f93a6a10e18570b0121026e5628506ecd33242e5ceb5fdafe4d3066b5c0f159b3c05a621ef65f177ea28600000000").unwrap()).unwrap();

        assert!(input_public_key(&prev.output[7].script_pubkey, &tx.input[0],).is_some());
    }
}
