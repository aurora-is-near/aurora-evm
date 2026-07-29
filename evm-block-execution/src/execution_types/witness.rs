use serde::{Deserialize, Serialize};

/// Represents the execution witness of a block. Contains lists of required preimages and
/// headers used during execution and verification.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionWitness {
    /// List of all hashed trie nodes preimages that were required during the execution of
    /// the block, including during state root recomputation.
    pub state: Vec<u8>,
    /// List of all contract codes (created / accessed) preimages that were required during
    /// the execution of the block, including during state root recomputation.
    pub contract_codes: Vec<u8>,
    /// List of all hashed account and storage keys (addresses and slots) preimages
    /// (unhashed account addresses and storage slots, respectively) that were required during
    /// the execution of the block.
    pub storage_keys: Vec<u8>,
    /// RLP-encoded block headers required for proving correctness of stateless execution.
    ///
    /// This collection stores block headers needed to verify:
    /// - State reads are correct (i.e. the code and accounts are correct wrt the pre-state root)
    /// - `BLOCKHASH` opcode execution results are correct
    pub headers: Vec<u8>,
}
