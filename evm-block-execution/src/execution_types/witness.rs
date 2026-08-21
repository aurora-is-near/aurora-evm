//! Data revealed to a stateless block execution.

/// Trie, code, key and ancestor preimages required to verify and execute a block.
///
/// Every field is a *list of items*, not one concatenated buffer: each trie node is hashed
/// individually to be matched against the pre-state root, each contract code against its code
/// hash, and each header is RLP-decoded on its own. A flat byte string could not be split back
/// into those items.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecutionWitness {
    /// Trie-node preimages required by execution and state-root recomputation.
    pub state: Vec<Vec<u8>>,
    /// Contract-code preimages required by execution and state-root recomputation.
    pub contract_codes: Vec<Vec<u8>>,
    /// Account-address and storage-slot preimages required for trie lookups.
    pub storage_keys: Vec<Vec<u8>>,
    /// RLP-encoded ancestor headers used to establish the pre-state and serve `BLOCKHASH`.
    /// Raw bytes are retained because their exact encoding determines each ancestor hash.
    pub headers: Vec<Vec<u8>>,
}
