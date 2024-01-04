// use bdk::{keys::DerivableKey, miniscript::Tap, template::DescriptorTemplate, KeychainKind};

// pub struct SilentPayment<K: DerivableKey<Tap>>(pub K, pub KeychainKind);

// impl<K: DerivableKey<Tap>> DescriptorTemplate for SilentPayment<K> {
//     fn build(
//         self,
//         network: bdk::bitcoin::Network,
//     ) -> Result<bdk::template::DescriptorTemplateOut, bdk::descriptor::DescriptorError> {
//         todo!()
//     }
// }
