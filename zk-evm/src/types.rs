use aurora_evm_jsontests::types::Spec;

pub fn from_spec(spec: aurora_evm_jsontests::types::Spec) -> Spec {
    match spec {
        aurora_evm_jsontests::types::Spec::Frontier => Spec::Frontier,
        aurora_evm_jsontests::types::Spec::Homestead => Spec::Homestead,
        aurora_evm_jsontests::types::Spec::Tangerine => Spec::Tangerine,
        aurora_evm_jsontests::types::Spec::SpuriousDragon => Spec::SpuriousDragon,
        aurora_evm_jsontests::types::Spec::Byzantium => Spec::Byzantium,
        aurora_evm_jsontests::types::Spec::Constantinople => Spec::Constantinople,
        aurora_evm_jsontests::types::Spec::Petersburg => Spec::Petersburg,
        aurora_evm_jsontests::types::Spec::Istanbul => Spec::Istanbul,
        aurora_evm_jsontests::types::Spec::Berlin => Spec::Berlin,
        aurora_evm_jsontests::types::Spec::London => Spec::London,
        aurora_evm_jsontests::types::Spec::Merge => Spec::Merge,
        aurora_evm_jsontests::types::Spec::Shanghai => Spec::Shanghai,
        aurora_evm_jsontests::types::Spec::Cancun => Spec::Cancun,
        aurora_evm_jsontests::types::Spec::Prague => Spec::Prague,
        aurora_evm_jsontests::types::Spec::Osaka => Spec::Osaka,
    }
}

// pub fn from_authorization_item(
//     item: aurora_evm_jsontests::types::transaction::AuthorizationItem,
// ) -> AuthorizationItem {
//     AuthorizationItem {
//         chain_id: item.chain_id,
//         address: item.address,
//         nonce: item.nonce,
//         r: item.r,
//         s: item.s,
//         v: item.v,
//         signer: item.signer,
//     }
// }
