//! [EIP-7594] `PeerDAS` size and transaction-limit constants.
//!
//! [EIP-7594]: https://eips.ethereum.org/EIPS/eip-7594

use crate::eips::eip4844::{FIELD_ELEMENT_BYTES_USIZE, FIELD_ELEMENTS_PER_BLOB_USIZE};

/// Number of field elements in a Reed-Solomon extended blob.
pub const FIELD_ELEMENTS_PER_EXT_BLOB: usize = FIELD_ELEMENTS_PER_BLOB_USIZE * 2;

/// Number of field elements in a cell.
pub const FIELD_ELEMENTS_PER_CELL: usize = 64;

/// The number of bytes in a cell.
pub const BYTES_PER_CELL: usize = FIELD_ELEMENTS_PER_CELL * FIELD_ELEMENT_BYTES_USIZE;

/// The number of cells in an extended blob.
pub const CELLS_PER_EXT_BLOB: usize = FIELD_ELEMENTS_PER_EXT_BLOB / FIELD_ELEMENTS_PER_CELL;

/// A wrapper version for EIP-7594 sidecar encoding.
pub const EIP_7594_WRAPPER_VERSION: u8 = 1;

/// Maximum number of blobs per transaction after Fusaka hardfork activation.
pub const MAX_BLOBS_PER_TX_FUSAKA: u64 = 6;

// A `Cell` type belongs with the blob payload, which this crate does not model — see the note in
// `eip4844`. Only the sizes are kept, because the fork's per-transaction blob cap is defined here.
