use std::collections::HashMap;

use bitcoin::secp256k1::{All, Parity, PublicKey, Secp256k1, SecretKey};
use bitcoin::{OutPoint, ScriptBuf};

use crate::address::SilentPaymentAddress;
use crate::outpoints::OutPoints;
use crate::SharedSecret;

pub struct SilentPayment {}

impl SilentPayment {
    pub fn builder(secp: &Secp256k1<All>) -> SilentPaymentBuilder {
        SilentPaymentBuilder::new(secp)
    }
}

pub struct SilentPaymentBuilder<'a> {
    recipients: Vec<SilentPaymentAddress>,
    a: Option<SecretKey>,
    outpoints: OutPoints,
    secp: &'a Secp256k1<All>,
}

impl<'a> SilentPaymentBuilder<'a> {
    pub fn new(secp: &Secp256k1<All>) -> SilentPaymentBuilder {
        SilentPaymentBuilder {
            secp,
            recipients: Default::default(),
            a: Default::default(),
            outpoints: Default::default(),
        }
    }

    pub fn add_recipient(
        &mut self,
        address: SilentPaymentAddress,
    ) -> &mut SilentPaymentBuilder<'a> {
        self.recipients.push(address);
        self
    }

    pub fn add_taproot_private_key(&mut self, key: SecretKey) -> &mut SilentPaymentBuilder<'a> {
        let (_, y_parity) = key.public_key(self.secp).x_only_public_key();

        let checked_key = if y_parity == Parity::Odd {
            key.negate()
        } else {
            key
        };

        let secret_key = self
            .a
            .map(|sk| sk.add_tweak(&checked_key.into()).unwrap())
            .unwrap_or(checked_key);

        self.a.replace(secret_key);
        self
    }

    pub fn add_private_key(&mut self, key: SecretKey) -> &mut SilentPaymentBuilder<'a> {
        let secret_key = self
            .a
            .map(|sk| sk.add_tweak(&key.into()).unwrap()) // TODO: unwrap
            .unwrap_or(key);
        self.a.replace(secret_key);
        self
    }

    pub fn add_outpoint(&mut self, outpoint: OutPoint) -> &mut SilentPaymentBuilder<'a> {
        self.outpoints.add(outpoint);
        self
    }

    #[must_use]
    pub fn build(&mut self) -> Vec<ScriptBuf> {
        let outpoints_hash = self.outpoints.hash();

        let mut groups: HashMap<PublicKey, Vec<(usize, PublicKey)>> = HashMap::new();

        // Enumerate to preserve order.
        self.recipients.iter().enumerate().for_each(|(index, r)| {
            groups
                .entry(r.scan_key())
                .or_default()
                .push((index, r.spend_key()));
        });

        let mut x: Vec<(usize, ScriptBuf)> = groups
            .into_iter()
            .flat_map(|(b_scan, b_ms)| {
                let shared_secret =
                    SharedSecret::new(outpoints_hash, b_scan, self.a.unwrap(), self.secp);

                b_ms.into_iter()
                    .enumerate()
                    .map(|(k, (index, b_m))| {
                        (
                            index,
                            shared_secret.destination_output(b_m, k as u32, self.secp),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect();

        x.sort_by_key(|(index, _)| *index);

        x.into_iter().map(|(_, script)| script).collect()
    }
}
