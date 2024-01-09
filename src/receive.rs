use std::collections::HashMap;

use bitcoin::secp256k1::{
    All, Parity, PublicKey, Scalar, Secp256k1, SecretKey, Signing, Verification, XOnlyPublicKey,
};
use bitcoin::{OutPoint, ScriptBuf, TxOut};

use crate::address::SilentPaymentAddress;
use crate::{Aggregate, InputNonce, SharedSecret, TweakData};

#[derive(Clone)]
pub struct Scanning {
    scan_key: SecretKey,
    spend_key: PublicKey,
    labels: Vec<Scalar>,
}

impl Scanning {
    pub fn new(scan_key: SecretKey, spend_key: PublicKey, labels: Vec<[u8; 32]>) -> Scanning {
        Scanning {
            scan_key,
            spend_key,
            labels: labels
                .into_iter()
                .map(|x| Scalar::from_be_bytes(x).unwrap())
                .collect(),
        }
    }

    pub fn scan_public_keys<'a>(
        &self,
        public_keys: &[XOnlyPublicKey],
        secp: &'a Secp256k1<All>,
    ) -> Option<ScanBuilder<'a>> {
        if public_keys.is_empty() {
            None
        } else {
            let mut builder = self.scan_builder(secp);
            public_keys.iter().for_each(|pk| {
                builder.add_output(pk.public_key(Parity::Even));
            });
            Some(builder)
        }
    }

    pub fn scan_script_pubkeys<'a>(
        &self,
        script_pubkeys: &[ScriptBuf],
        secp: &'a Secp256k1<All>,
    ) -> Option<ScanBuilder<'a>> {
        let public_keys = script_pubkeys
            .iter()
            .filter_map(|spk| {
                if spk.is_v1_p2tr() {
                    spk.as_bytes()
                        .get(2..)
                        .and_then(|b| XOnlyPublicKey::from_slice(b).ok())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        self.scan_public_keys(&public_keys, secp)
    }

    // TODO: put secp into Scanning?
    pub fn scan_outputs<'a>(
        &self,
        outputs: &[TxOut],
        secp: &'a Secp256k1<All>,
    ) -> Option<ScanBuilder<'a>> {
        self.scan_script_pubkeys(
            &outputs
                .iter()
                .map(|o| o.script_pubkey.clone())
                .collect::<Vec<_>>(),
            secp,
        )
    }

    pub fn scan_builder<'a>(&self, secp: &'a Secp256k1<All>) -> ScanBuilder<'a> {
        ScanBuilder::new(self.clone(), secp)
    }

    pub fn addresses<C>(&self, secp: &Secp256k1<C>) -> Vec<SilentPaymentAddress>
    where
        C: Signing + Verification,
    {
        let scan_key = self.scan_key.public_key(secp);

        let mut addrs = vec![SilentPaymentAddress::new(self.spend_key, scan_key)];

        self.labels.iter().for_each(|l| {
            let b_m = self.spend_key.add_exp_tweak(secp, l).unwrap();
            addrs.push(SilentPaymentAddress::new(b_m, scan_key))
        });

        addrs
    }
}

pub struct ScanBuilder<'a> {
    scanning: Scanning,
    input_public_key: Aggregate<PublicKey>,
    input_nonce: InputNonce,
    outputs: Vec<PublicKey>,
    secp: &'a Secp256k1<All>,
}

impl<'a> ScanBuilder<'a> {
    pub fn new(scanning: Scanning, secp: &Secp256k1<All>) -> ScanBuilder {
        ScanBuilder {
            scanning,
            secp,
            input_public_key: Default::default(),
            input_nonce: Default::default(),
            outputs: Default::default(),
        }
    }

    pub fn add_xonly_public_key(&mut self, key: &XOnlyPublicKey) -> &mut ScanBuilder<'a> {
        self.add_public_key(&key.public_key(Parity::Even))
    }

    pub fn add_public_key(&mut self, public_key: &PublicKey) -> &mut ScanBuilder<'a> {
        self.input_public_key.add_key(public_key);
        self.input_nonce.add_input_public_key(public_key).unwrap();
        self
    }

    pub fn add_outpoint(&mut self, outpoint: &OutPoint) -> &mut ScanBuilder<'a> {
        self.input_nonce.add_outpoint(outpoint);
        self
    }

    pub fn add_output(&mut self, output: PublicKey) -> &mut ScanBuilder<'a> {
        self.outputs.push(output);
        self
    }

    pub fn xxx(self) -> HashMap<XOnlyPublicKey, TweakData> {
        let shared_secret = SharedSecret::new(
            self.input_nonce.hash().unwrap(),
            self.input_public_key.get().unwrap(),
            self.scanning.scan_key,
            self.secp,
        );

        println!("2> {:?}", shared_secret);

        let labels = self
            .scanning
            .labels
            .iter()
            .flat_map(|&label| {
                let label_public_key = SecretKey::from_slice(&label.to_be_bytes())
                    .unwrap()
                    .public_key(self.secp);
                [
                    (label_public_key, label),
                    (label_public_key.negate(self.secp), label),
                ]
            })
            .collect::<HashMap<_, _>>();

        self.outputs
            .iter()
            .fold((HashMap::new(), 0u32), |(mut acc, k), &output| {
                let (pk, tk) =
                    shared_secret.destination_public_key(self.scanning.spend_key, k, self.secp);

                let next_output = if output == pk {
                    Some((output.x_only_public_key().0, TweakData::new(tk)))
                } else {
                    [output, output.negate(self.secp)]
                        .iter()
                        .filter_map(|x| x.combine(&pk.negate(self.secp)).ok())
                        .find_map(|x| labels.get_key_value(&x))
                        .and_then(|(x, &l)| {
                            x.combine(&pk).ok().map(|x| {
                                (x.x_only_public_key().0, TweakData::new_with_label(tk, l))
                            })
                        })
                };

                if let Some((out, tk)) = next_output {
                    acc.insert(out, tk);
                    (acc, k + 1)
                } else {
                    (acc, k)
                }
            })
            .0
    }
}
