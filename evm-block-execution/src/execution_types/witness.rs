/// Represents the execution witness of a block. Contains lists of required preimages and
/// headers used during execution and verification.
///
/// Every field is a *list of items*, not one concatenated buffer: each trie node is hashed
/// individually to be matched against the pre-state root, each contract code against its code
/// hash, and each header is RLP-decoded on its own. A flat byte string could not be split back
/// into those items.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecutionWitness {
    /// List of all hashed trie nodes preimages that were required during the execution of
    /// the block, including during state root recomputation.
    pub state: Vec<Vec<u8>>,
    /// List of all contract codes (created / accessed) preimages that were required during
    /// the execution of the block, including during state root recomputation.
    pub contract_codes: Vec<Vec<u8>>,
    /// List of all hashed account and storage keys (addresses and slots) preimages
    /// (unhashed account addresses and storage slots, respectively) that were required during
    /// the execution of the block.
    pub storage_keys: Vec<Vec<u8>>,
    /// RLP-encoded block headers required for proving correctness of stateless execution.
    ///
    /// This collection stores block headers needed to verify:
    /// - State reads are correct (i.e. the code and accounts are correct wrt the pre-state root)
    /// - `BLOCKHASH` opcode execution results are correct
    ///
    /// Kept as raw bytes rather than decoded [`Header`](crate::block::Header)s because the
    /// ancestor hash is `keccak256` of exactly these bytes.
    pub headers: Vec<Vec<u8>>,
}
