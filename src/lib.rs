//! This library provides functions for working with sending and receiving
//! Bitcoin Silent Payments according to BIP 352 proposal.
use bitcoin::consensus::serialize;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::key::TapTweak;
use bitcoin::secp256k1::{
    Error as SecpError, Keypair, Parity, PublicKey, Scalar, Secp256k1, SecretKey, Signing,
    Verification, XOnlyPublicKey,
};
use bitcoin::{OutPoint, Script, ScriptBuf, TxIn};

pub mod address;
#[cfg(feature = "receive")]
pub mod receive;
#[cfg(feature = "send")]
pub mod send;
#[cfg(feature = "spend")]
pub mod spend;

/// An output that has been detected as a Silent Payment together with
/// all data that are needed to spend it. Wallets should index this.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Eq, Ord)]
pub struct SilentPaymentOutput {
    public_key: XOnlyPublicKey,
    tweak: Scalar,
    label: Option<[u8; 32]>,
}

impl std::hash::Hash for SilentPaymentOutput {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.public_key.hash(state);
        self.tweak.to_be_bytes().hash(state);
        self.label.hash(state);
    }
}

impl SilentPaymentOutput {
    pub fn new(public_key: XOnlyPublicKey, tweak: Scalar) -> Self {
        Self {
            public_key,
            tweak,
            label: None,
        }
    }

    pub fn new_with_label(public_key: XOnlyPublicKey, tweak: Scalar, label: [u8; 32]) -> Self {
        Self {
            public_key,
            tweak,
            label: Some(label),
        }
    }

    pub fn public_key(&self) -> XOnlyPublicKey {
        self.public_key
    }

    pub fn tweak(&self) -> Scalar {
        self.tweak
    }

    pub fn label(&self) -> Option<[u8; 32]> {
        self.label
    }
}

#[derive(Default)]
pub struct InputHash {
    /// Holds the least (so far) outpoint bytes.
    least_outpoint: Option<[u8; 36]>,

    // TODO: Remove when test vector updated.
    #[deprecated = "specification changed"]
    outpoints: Vec<[u8; 36]>,

    /// Holds aggregated input public key.
    public_key: Aggregate<PublicKey>,
}

impl InputHash {
    /// Creates new, empty input hash.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers new outpoint that is subject of calculation of the input hash.
    pub fn add_outpoint(&mut self, outpoint: &OutPoint) -> &mut InputHash {
        let bytes: [u8; 36] = serialize(outpoint)
            .try_into()
            .expect("outpoint serializes to 36 bytes");
        self.add_outpoint_serialized(bytes)
    }

    /// Registers new already-serialized outpoint that is subject of calculation of the input hash.
    pub fn add_outpoint_serialized(&mut self, bytes: [u8; 36]) -> &mut InputHash {
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

    pub fn add_input_public_key(&mut self, public_key: &PublicKey) -> Option<&mut InputHash> {
        self.public_key.add_key(public_key)?;
        Some(self)
    }

    /// Returns input hash.
    pub fn hash(self) -> Result<Scalar, InputHashError> {
        let mut engine = sha256::Hash::engine();

        // TODO: Remove when test vector updated.
        self.outpoints.iter().for_each(|o| engine.input(o));

        // TODO: Uncomment when test vector updated
        // let outpoint = self.least_outpoint.ok_or(InputHashError::NoOutPoint)?;
        // engine.input(&outpoint);
        // let public_key = self.public_key.get().ok_or(InputHashError::NoPublicKey)?;
        // engine.input(&public_key.serialize());

        let hash = sha256::Hash::from_engine(engine);
        Scalar::from_be_bytes(hash.to_byte_array()).map_err(|_| InputHashError::InvalidValue)
    }
}

#[derive(Debug)]
pub enum InputHashError {
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
        input_hash: Scalar,
        pk: PublicKey,
        sk: SecretKey,
        secp: &Secp256k1<C>,
    ) -> SharedSecret {
        let ecdh = sk.mul_tweak(&input_hash).unwrap();
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
) -> Result<Keypair, SecpError> {
    // d = b_spend + t_k + hash(b_scan || m)
    let d = spend_key.add_tweak(tweak)?.add_tweak(label)?;
    Ok(Keypair::from_secret_key(secp, &d))
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
    } else if prevout.is_p2sh()
        && matches!(input.script_sig.as_bytes(), [0x16, 0x0, 0x14, x@..] if x.len() == 20)
    {
        input
            .witness
            .last()
            .and_then(|b| PublicKey::from_slice(b).ok())
    } else {
        None
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

    #[test]
    fn extract_pk_from_sh_wpkh() {
        let tx = deserialize::<Transaction>(&Vec::from_hex("02000000000103bd1c1428173c1f50f6cce22c3fb64dbadea78b8c11942117a96a492f28be3640020000006a47304402203129d2a271e1786569777a74b7384af7c9617af89f0b6ece0b17402870a3f84702201ee2b3f8b7d788a92ad3205885b3d5dcbd993078484e5fc9fbdf5cd991760f7c012103786af4b32017ec640dba2d2a7e1fd5aa4a231a658e4cbc114d51c031576e19bcfdffffff153968ba0daf73e159223739a071316d5e9f5683262eb0d7c79f28d29cb396da0400000017160014bf0b3a458c7e3103c3c47ae79a0ed87ac4cac0c3fdfffffff6492a91c3e1d804a949b902a3a8c61253532307879e42875a5d2edaca89c23800000000171600149f33de9595d3f35c999afe440e24c4e6aae536a7fdffffff029c0209000000000017a914725545ba42319990559a1fe575801f3ddb01356d87f7c999d5000000001976a914cebb2851a9c7cfe2582c12ecaf7f3ff4383d1dc088ac00024730440220013409fe1d7afc06d6995d05bb7e1b41964d7eebd797b5de2d2ebd636db1bb590220034a23aa52f1d888587164347e9c4d33f97d2608380e31d7ef3f5f96af6b77e4012103f575b6be65db8c23595572c39deac371dcfb295df23d9794a585b98a94d143b10247304402207a51ecb60e0b3cdd4f841f5b1af23f16c7b9410b36716f875e15b535c2979b410220686b12b4e9d9b712a73d03cad75606d17241bc1d5124b6ef211eff08c767d2dd0121025ce070fd89c603855a4e97686a12652c4c17b658380078c5c44c300d5b06c90c00000000").unwrap()).unwrap();

        let prev = deserialize::<Transaction>(&Vec::from_hex("010000000001015a7ba039bbdd1988b4426e928cf489b58889d75cf774010a967eda69a9b78d550000000000ffffffff1d607e10030000000016001468870b46c8214d13f33140dcd1f1962f05db0076a54d9f0100000000160014dc6bf86354105de2fcd9868a2b0376d6731cb92fb395060000000000160014583fef011b214f528b9e255cc0cb7f1764f20eb418ca02000000000017a91473a457d27346a2d0e8eb8a4387084f876a9b042e870a7bbd3b0000000017a914dd55b64160f3ec0d2a82af28d76524d368c124d587a8d801000000000017a91441c35ee5bcd7dd4c818d2556a870fe540ecc4a8987a02e63000000000016001403ee907981a26744ee915ab81254f736ac9792b58c0b0400000000002251206e1e6c0c6574ac2e4c8658481da1521b249932bfcd0bfc8e6b08e8fb56338183b850eb0b0000000017a9147ee44352cdc2cdc3036ae60f9eda0d51289d054c877cec2e0000000000160014d595129a2f0a832dfce5281beccbf824d9ed121c8071040000000000225120b4059360fd17d744417b713e4ada1808be8b73895716f749926073a0df4d91b43825980000000000160014fbf9fc56bfc3c43909ab064e280232cc1cffc7d9e1450500000000002251202ac197b7d66c494f45b01f3d177e88793b8d6c2d3f2a491cd9d56653a8d5c87863b204000000000016001488447d589ada506a048524b63da2cb5d27ecc4a814f426000000000016001487525cfaef66f71fb998ca775678020182f645967e7d08000000000017a9148ae9fa7b9ebdfc01c25b672ace9532cb6bd2e03a873a12300000000000160014158125b466f5c8282a5521203b2c2f0083382d0538370d0000000000160014b494268816787bbfb7dbcf309fee14535b3b82489a406e01000000001600147e715f78f0ecc163c524c9bea186d6905004a17985bc0200000000001976a914e2c2e39dd97c2ec71561263f879336f0d8a3645588ac80fc17e30000000017a914afb5676cc5e35befc0c345fa086e1a14c279cfcd874180290000000000160014092dede65e92bdbf28709efb9f807cc1e482f83cb82d2400000000001600146e08a5d80088f70e5f9be72d9159ed6b979ba7a6a149470100000000160014e8ddcdbad604b250e20009e7c9226e978cbf1210ec14060000000000225120a5777a3d41b7f981f3638cab65b1c2f9bb0555c3f5316d3e47df96995f534dcb41bc20000000000017a914ffdd09e91cfe0f169e14fbfb8a342c0eb420921587781b6c05000000001976a9141ac27e7b667a3195f2cac8a7f32438e1f5aadca588acb5e20f0000000000160014c95d561e7c8a7c60bffa80b800f5493b4dea26e618541b000000000017a914edc9a07756488398aa0264849a5d4a334b6142b58702483045022100b98a8716490de6a03d3f21b757fec8003a34d8c2d584c1ddcdcb72944fb33c29022075679082bda1e7d307d393014416248e60748fb46227c9a77a22df15204834cb012102174ee672429ff94304321cdae1fc1e487edf658b34bd1d36da03761658a2bb0900000000").unwrap()).unwrap();

        assert!(input_public_key(&prev.output[4].script_pubkey, &tx.input[1],).is_some());
    }
}
