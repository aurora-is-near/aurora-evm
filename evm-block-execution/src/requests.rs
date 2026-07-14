//! EIP-7685 general-purpose requests container.

use crate::crypto::sha256;
use primitive_types::H256;

/// Container of EIP-7685 requests. Each stored entry is `request_type || request_data`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Requests(Vec<Vec<u8>>);

impl Requests {
    /// Creates an empty container.
    #[must_use]
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// Appends a request, prefixing `data` with its one-byte `request_type`.
    ///
    /// A request with empty `data` (only the type byte) is still stored but is ignored by
    /// [`Self::requests_hash`], matching the EIP-7685 hashing rule.
    pub fn push_request_with_type(&mut self, request_type: u8, data: impl AsRef<[u8]>) {
        let data = data.as_ref();
        let mut entry = Vec::with_capacity(data.len() + 1);
        entry.push(request_type);
        entry.extend_from_slice(data);
        self.0.push(entry);
    }

    /// Raw request entries (`request_type || request_data`).
    // `missing_const_for_fn` is a false positive here: returning `&self.0` as `&[Vec<u8>]`
    // needs a deref coercion, which is not permitted in a `const fn`.
    #[allow(clippy::missing_const_for_fn)]
    #[must_use]
    pub fn as_slice(&self) -> &[Vec<u8>] {
        &self.0
    }

    /// Whether the container holds no requests.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// EIP-7685 requests hash: `sha256( sha256(req_0) ++ sha256(req_1) ++ ... )`.
    ///
    /// Entries with only a type byte (empty data) are skipped, and entries are ordered by their
    /// request type. The canonical EIP-7685 form has exactly one request object per type; a
    /// **stable** sort is used so the hash stays deterministic even if several entries share a
    /// type (their relative insertion order is preserved). With no non-empty requests this is
    /// `sha256("")` (i.e. `EMPTY_REQUESTS_HASH`).
    #[must_use]
    pub fn requests_hash(&self) -> H256 {
        let mut entries: Vec<&Vec<u8>> = self.0.iter().filter(|req| req.len() > 1).collect();
        entries.sort_by_key(|req| req[0]);
        let mut concatenated = Vec::with_capacity(entries.len() * 32);
        for req in entries {
            concatenated.extend_from_slice(sha256(req).as_bytes());
        }
        sha256(&concatenated)
    }
}

#[cfg(test)]
mod tests {
    use super::Requests;
    use crate::constants::{request_type, EMPTY_REQUESTS_HASH};
    use crate::crypto::sha256;

    #[test]
    fn empty_requests_hash_is_sha256_of_empty() {
        assert_eq!(Requests::new().requests_hash(), EMPTY_REQUESTS_HASH);
        assert!(Requests::new().is_empty());
    }

    #[test]
    fn type_only_request_is_ignored() {
        let mut reqs = Requests::new();
        reqs.push_request_with_type(request_type::WITHDRAWAL, []); // only the type byte
                                                                   // The entry is stored, but contributes nothing to the hash.
        assert!(!reqs.is_empty());
        assert_eq!(reqs.requests_hash(), EMPTY_REQUESTS_HASH);
    }

    #[test]
    fn single_request_hash_matches_definition() {
        let mut reqs = Requests::new();
        reqs.push_request_with_type(request_type::WITHDRAWAL, [0xaa, 0xbb]);
        // requests_hash = sha256(sha256(0x01 || 0xaa 0xbb))
        let inner = sha256(&[request_type::WITHDRAWAL, 0xaa, 0xbb]);
        let expected = sha256(inner.as_bytes());
        assert_eq!(reqs.requests_hash(), expected);
    }

    #[test]
    fn hash_is_independent_of_insertion_order() {
        let mut a = Requests::new();
        a.push_request_with_type(request_type::CONSOLIDATION, [0x02]);
        a.push_request_with_type(request_type::DEPOSIT, [0x00]);
        let mut b = Requests::new();
        b.push_request_with_type(request_type::DEPOSIT, [0x00]);
        b.push_request_with_type(request_type::CONSOLIDATION, [0x02]);
        assert_eq!(a.requests_hash(), b.requests_hash());
        assert_ne!(a.requests_hash(), EMPTY_REQUESTS_HASH);
    }

    #[test]
    fn two_requests_hash_matches_manual_computation() {
        let mut reqs = Requests::new();
        reqs.push_request_with_type(request_type::DEPOSIT, [0x0a, 0x0b, 0x0c]);
        reqs.push_request_with_type(request_type::WITHDRAWAL, [0x0d, 0x0e, 0x0f]);
        // Independently reproduce the EIP-7685 definition: per-request sha256 (sorted by type),
        // concatenated, then sha256 of the concatenation.
        let h0 = sha256(&[request_type::DEPOSIT, 0x0a, 0x0b, 0x0c]);
        let h1 = sha256(&[request_type::WITHDRAWAL, 0x0d, 0x0e, 0x0f]);
        let mut concatenated = Vec::with_capacity(64);
        concatenated.extend_from_slice(h0.as_bytes());
        concatenated.extend_from_slice(h1.as_bytes());
        assert_eq!(reqs.requests_hash(), sha256(&concatenated));
    }

    #[test]
    fn hash_changes_with_request_data() {
        let mut a = Requests::new();
        a.push_request_with_type(request_type::DEPOSIT, [0x01]);
        let mut b = Requests::new();
        b.push_request_with_type(request_type::DEPOSIT, [0x02]);
        assert_ne!(a.requests_hash(), b.requests_hash());
    }

    #[test]
    fn stored_entry_prepends_type_byte() {
        let mut reqs = Requests::new();
        reqs.push_request_with_type(request_type::DEPOSIT, [0x11, 0x22]);
        assert_eq!(reqs.as_slice(), &[vec![0x00, 0x11, 0x22]]);
    }
}
