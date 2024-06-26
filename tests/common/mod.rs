use std::collections::HashMap;

use bitcoin::bip32::{DerivationPath, Fingerprint, Xpriv};
use bitcoin::secp256k1::{All, Secp256k1, SecretKey};
use miniscript::descriptor::{DescriptorSecretKey, ShInner};
use miniscript::{Descriptor, DescriptorPublicKey};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ListDescriptorsResult {
    pub wallet_name: String,
    pub descriptors: Vec<ListDescriptorsDescriptor>,
}

#[derive(Debug, Deserialize)]
pub struct ListDescriptorsDescriptor {
    desc: String,
}

#[derive(Debug, Deserialize)]
pub struct GetAddress {
    pub desc: String,
}

pub struct PrivateKeys<'a> {
    pub keys: HashMap<Fingerprint, Xpriv>,
    pub secp: &'a Secp256k1<All>,
}

impl<'a> PrivateKeys<'a> {
    pub fn for_descriptor(&self, desc: &Descriptor<DescriptorPublicKey>) -> Option<SecretKey> {
        let origin = extract_origin(desc)?;
        let xpriv = self.keys.get(&origin.0)?;
        let x = xpriv.derive_priv(self.secp, &origin.1).ok()?;
        Some(x.private_key)
    }
}

pub fn collect_xprivs(
    secp: &Secp256k1<All>,
    descs: &[ListDescriptorsDescriptor],
) -> HashMap<Fingerprint, Xpriv> {
    descs
        .iter()
        .filter_map(|d| Descriptor::parse_descriptor(secp, &d.desc).ok())
        .flat_map(|x| x.1.values().cloned().collect::<Vec<_>>())
        .filter_map(|x| match x {
            DescriptorSecretKey::XPrv(x) => Some(x.xkey),
            _ => None,
        })
        .map(|x| (x.fingerprint(secp), x))
        .collect::<HashMap<_, _>>()
}

pub fn extract_origin(
    desc: &Descriptor<DescriptorPublicKey>,
) -> Option<&(Fingerprint, DerivationPath)> {
    fn get_origin(pk: &DescriptorPublicKey) -> Option<&(Fingerprint, DerivationPath)> {
        match pk {
            DescriptorPublicKey::Single(s) => s.origin.as_ref(),
            DescriptorPublicKey::XPub(x) => x.origin.as_ref(),
            DescriptorPublicKey::MultiXPub(_) => None,
        }
    }

    match desc {
        Descriptor::Bare(_) => None,
        Descriptor::Pkh(p) => get_origin(p.as_inner()),
        Descriptor::Wpkh(w) => get_origin(w.as_inner()),
        Descriptor::Sh(s) => match s.as_inner() {
            ShInner::Wpkh(w) => get_origin(w.as_inner()),
            _ => None,
        },
        Descriptor::Wsh(_) => None,
        Descriptor::Tr(tr) => get_origin(tr.internal_key()),
    }
}
