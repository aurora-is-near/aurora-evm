use crate::block::{Block, UncompressedPublicKey};
use crate::execution_types::witness::ExecutionWitness;

pub fn stateless_validation(
    _block: Block,
    _public_keys: Vec<UncompressedPublicKey>,
    _witness: ExecutionWitness,
) {
}
