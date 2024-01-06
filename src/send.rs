//! Everything for sending Silent Payments.
//!
//! To send a Silent Payment, create new instance of [`SilentPayment`]
//! and add all required and available data: addresses of recipients,
//! outpoints that will be spent by the final transaction
//! and private keys that were used to sign these outpoints. At then
//! end [`generate_output_scripts`](SilentPayment::generate_output_scripts)
//! will return a list of output scripts to be included in the transaction.
//!
//! The output scripts are in the same order in which the recipients were added.
//!
//! # Example
//!
//! ```
//! # use bip352::address::SilentPaymentAddress;
//! # use bip352::send::SilentPayment;
//! # use bitcoin::hashes::sha256d::Hash;
//! # use bitcoin::secp256k1::{Secp256k1, SecretKey, Error};
//! # use bitcoin::{OutPoint, ScriptBuf, Txid};
//! let secp = Secp256k1::new();
//! let mut sp = SilentPayment::new(&secp);
//!
//! // Add recipient
//! let address = SilentPaymentAddress::from_bech32("sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv").expect("parse address");
//! sp.add_recipient(address);
//!
//! // Add selected outpoints (in any order)
//! let outpoint: OutPoint = OutPoint::null();
//! sp.add_outpoint(outpoint);
//!
//! // Add private keys that sign them (in any order)
//! let private_key: SecretKey = SecretKey::from_slice(&[1; 32])?;
//! sp.add_private_key(private_key);
//!
//! // And get the output scripts (same order as recipients)
//! let outputs: Vec<ScriptBuf> = sp.generate_output_scripts();
//!
//! // outputs:
//! // [
//! //   Script(
//! //     OP_PUSHNUM_1
//! //     OP_PUSHBYTES_32
//! //     81c5bba8d342c276158972be308d869c860e3953fcabac80ddb88ff0585b9436
//! //   )
//! // ]
//! # Ok::<(), Error>(())
//! ```
use std::collections::HashMap;

use bitcoin::bip32::{ExtendedPrivKey, Fingerprint};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{All, Parity, PublicKey, Secp256k1, SecretKey};
use bitcoin::{OutPoint, ScriptBuf};

use crate::address::SilentPaymentAddress;
use crate::{input_public_key, Aggregate, InputNonce, SharedSecret};

pub struct SilentPayment<'a> {
    recipients: Vec<SilentPaymentAddress>,
    input_secret_key: Aggregate<SecretKey>,
    input_nonce: InputNonce,
    secp: &'a Secp256k1<All>,
}

impl<'a> SilentPayment<'a> {
    pub fn new(secp: &Secp256k1<All>) -> SilentPayment {
        SilentPayment {
            secp,
            recipients: Default::default(),
            input_secret_key: Default::default(),
            input_nonce: Default::default(),
        }
    }

    pub fn add_recipient(&mut self, address: SilentPaymentAddress) -> &mut SilentPayment<'a> {
        self.recipients.push(address);
        self
    }

    pub fn add_taproot_private_key(&mut self, key: SecretKey) -> &mut SilentPayment<'a> {
        let (_, y_parity) = key.public_key(self.secp).x_only_public_key();

        let checked_key = if y_parity == Parity::Odd {
            key.negate()
        } else {
            key
        };

        self.add_private_key(checked_key)
    }

    /// Unconditionally registers the given private key for the Silent Payment.
    /// **Warning**: Each of the private keys added using this method is going to be
    /// used and will be unchanged. That may render the Silent Payment to be incorrect
    /// and unspendable. If unsure, use _TBA_ instead.
    ///
    /// ### Under the hood
    /// These private keys, together with previous outpoints, are used
    /// to derive shared secret using a version of Diffie-Hellman exchange. However, only
    /// private keys signing inputs with certain properties should be used. If a private
    /// key is added that does not sign a correct input, recipient will have no way
    /// how to identify and spend the payment.
    ///
    /// Additionally, private keys signing taproot inputs have to be checked for Y-coordinate
    /// ([`add_taproot_private_key`](Self::add_taproot_private_key) checks for them). If this method is used to add private
    /// key signing taproot output, the Silent Payment may be unspendable.
    pub fn add_private_key(&mut self, key: SecretKey) -> &mut SilentPayment<'a> {
        self.input_secret_key.add_key(&key);
        self.input_nonce
            .add_input_public_key(&key.public_key(self.secp))
            .unwrap();
        self
    }

    /// Unconditionally registers the given outpoint for the Silent Payment.
    /// **Warning**: Each of the outpoints added using this method is going to be used. That
    /// may render the Silent Payment to be incorrect and unspendable. If unsure, use _TBA_ instead.
    ///
    /// ### Under the hood
    /// These outpoints, together with private keys, are used to derive
    /// shared secret using a version of Diffie-Hellman exchange. However, only outpoints
    /// with certain properties should be used. If an outpoint that does not meet these
    /// properties is added, recipient will have no way how to identify and spend the payment.
    pub fn add_outpoint(&mut self, outpoint: OutPoint) -> &mut SilentPayment<'a> {
        self.input_nonce.add_outpoint(&outpoint);
        self
    }

    /// Registers all relevant outpoints from a given PSBT and their private keys.
    /// If the PSBT contains all inputs selected for the transaction and all
    /// private keys that are going to sign them, calling this method is all that
    /// is needed to regiter outpoints and private keys.
    ///
    /// Returns all private keys that were not found but are needed. They can be
    /// added manually by [`add_private_key`] or [`add_taproot_private_key`].
    // TODO: Return list of required keys
    pub fn add_from_psbt(
        &mut self,
        psbt: &Psbt,
        xprivs: &HashMap<Fingerprint, ExtendedPrivKey>,
    ) -> &mut SilentPayment<'a> {
        psbt.inputs
            .iter()
            .zip(psbt.unsigned_tx.input.iter())
            .filter(|(psbt_input, tx_input)| {
                psbt_input
                    .witness_utxo
                    .as_ref()
                    .and_then(|txout| input_public_key(tx_input, txout))
                    .is_some()
            })
            .for_each(|(psbt_input, tx_input)| {
                self.add_outpoint(tx_input.previous_output);

                let der = &psbt_input.bip32_derivation;
                let (_pk, (fp, dp)) = der.first_key_value().unwrap();
                let xpriv = xprivs.get(fp).unwrap();
                let sk = xpriv.derive_priv(self.secp, dp).unwrap().to_priv();

                // TODO: Verify public key of tx_input
                // TODO: Check for taproot

                self.add_private_key(sk.inner);
            });

        self
    }

    // TODO: Return list of required keys
    pub fn add_from_psbt_no_keys(&mut self, psbt: &Psbt) -> &mut SilentPayment<'a> {
        self.add_from_psbt(psbt, &Default::default())
    }

    #[must_use]
    pub fn generate_output_scripts(self) -> Vec<ScriptBuf> {
        let input_nonce = self.input_nonce.hash().unwrap();
        let input_secret_key = self.input_secret_key.get().unwrap();

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
                    SharedSecret::new(input_nonce, b_scan, input_secret_key, self.secp);

                b_ms.into_iter().zip(0..).map(move |((index, b_m), k)| {
                    (index, shared_secret.destination_output(b_m, k, self.secp))
                })
            })
            .collect();

        x.sort_by_key(|(index, _)| *index);

        x.into_iter().map(|(_, script)| script).collect()
    }
}
