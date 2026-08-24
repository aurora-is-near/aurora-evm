//! The [EIP-2718] envelope: the transaction types as one value, and the type-byte dispatch
//! between bytes and the typed form.
//!
//! Encoding is **total** here — every variant holds exactly the fields its type has, so there is
//! nothing left to check. Decoding is the only fallible direction, and it is where every consensus
//! rule about the byte form lives.
//!
//! [EIP-2718]: https://eips.ethereum.org/EIPS/eip-2718

use super::{
    SignedTxEip1559, SignedTxEip2930, SignedTxEip4844, SignedTxEip7702, SignedTxLegacy,
    TxDecodeError, eip1559, eip2930, eip4844, eip7702,
};

use crate::crypto::keccak256;
use crate::rlp_strict;
use crate::transaction::TxType;
use crate::transaction::env::TxEnv;
use crate::transaction::signature::TxSignature;
use crate::transaction::signed_authorization::SignedAuthorization;
use core::cmp::Ordering;
use primitive_types::H160;
use primitive_types::H256;

/// A signed transaction of any type, each in the shape its own EIP fixes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignedTxEnvelope {
    /// Pre-EIP-2718: a bare RLP list with no type byte.
    Legacy(SignedTxLegacy),
    /// EIP-2930, type byte `0x01`.
    Eip2930(SignedTxEip2930),
    /// EIP-1559, type byte `0x02`.
    Eip1559(SignedTxEip1559),
    /// EIP-4844, type byte `0x03`.
    Eip4844(SignedTxEip4844),
    /// EIP-7702, type byte `0x04`.
    Eip7702(SignedTxEip7702),
}

impl SignedTxEnvelope {
    /// The transaction's type.
    #[must_use]
    pub const fn tx_type(&self) -> TxType {
        match self {
            Self::Legacy(_) => TxType::Legacy,
            Self::Eip2930(_) => TxType::Eip2930,
            Self::Eip1559(_) => TxType::Eip1559,
            Self::Eip4844(_) => TxType::Eip4844,
            Self::Eip7702(_) => TxType::Eip7702,
        }
    }

    /// The EIP-2718 encoding: the type byte followed by the field list, or a bare RLP list for a
    /// legacy transaction.
    ///
    /// This is the form the transactions trie and the transaction hash are built from.
    #[must_use]
    pub fn encode_2718(&self) -> Vec<u8> {
        let mut stream = rlp::RlpStream::new();
        self.encode_2718_in(&mut stream).to_vec()
    }

    /// Writes the EIP-2718 encoding into a dedicated scratch stream and returns the written slice.
    ///
    /// Kept crate-private because `stream` is cleared and must be reserved for this operation. Reusing
    /// it across a block retains the backing allocation. If it was created over an existing buffer,
    /// the returned slice excludes that prefix and covers only this envelope.
    ///
    /// # Panics
    /// Panics if a transaction encoder violates its fixed RLP-list arity. In debug builds, also
    /// panics if `stream` already contains an unfinished list instead of a reusable scratch value.
    pub(crate) fn encode_2718_in<'stream>(
        &self,
        stream: &'stream mut rlp::RlpStream,
    ) -> &'stream [u8] {
        // `clear()` would silently discard an enclosing list; catch misuse of the scratch contract
        // while developing, without charging the zkVM release path.
        debug_assert!(
            stream.is_finished(),
            "the EIP-2718 scratch stream must not contain an unfinished list"
        );
        stream.clear();
        let base = stream.as_raw().len();
        match self {
            // A legacy transaction carries no type byte: it *is* the RLP list.
            Self::Legacy(tx) => {
                stream.append(tx);
            }
            Self::Eip2930(tx) => {
                stream.append_raw(&[eip2930::TYPE_BYTE], 0);
                stream.append(tx);
            }
            Self::Eip1559(tx) => {
                stream.append_raw(&[eip1559::TYPE_BYTE], 0);
                stream.append(tx);
            }
            Self::Eip4844(tx) => {
                stream.append_raw(&[eip4844::TYPE_BYTE], 0);
                stream.append(tx);
            }
            Self::Eip7702(tx) => {
                stream.append_raw(&[eip7702::TYPE_BYTE], 0);
                stream.append(tx);
            }
        }
        // `as_raw()` bypasses `RlpStream::out()` and its completion check, so keep a mismatched
        // bounded field count fail-closed in release builds too.
        assert!(stream.is_finished(), "EIP-2718 encoding left an open list");
        &stream.as_raw()[base..]
    }

    /// Decodes an EIP-2718 encoded transaction.
    ///
    /// # Errors
    /// [`TxDecodeError`] if the input is empty, carries an unknown or reserved type byte, starts with
    /// neither a type byte nor a legacy-list prefix, is not well-formed RLP for its type, encodes a
    /// creation for a type that forbids one, or does not cover its buffer exactly — `RlpIsTooShort`
    /// when it declares more than it carries, `RlpIsTooBig` when bytes follow it, and
    /// `RlpInvalidLength` when the declared length overflows a `usize`.
    pub fn decode_2718(bytes: &[u8]) -> Result<Self, TxDecodeError> {
        let (&first, payload) = bytes.split_first().ok_or(TxDecodeError::Empty)?;

        // EIP-2718: https://eips.ethereum.org/EIPS/eip-2718
        // Section:  Backwards Compatibility
        match first {
            eip2930::TYPE_BYTE => {
                check_covers_exactly(payload)?;
                Ok(Self::Eip2930(SignedTxEip2930::decode_strict(
                    &rlp::Rlp::new(payload),
                )?))
            }
            eip1559::TYPE_BYTE => {
                check_covers_exactly(payload)?;
                Ok(Self::Eip1559(SignedTxEip1559::decode_strict(
                    &rlp::Rlp::new(payload),
                )?))
            }
            eip4844::TYPE_BYTE => {
                check_covers_exactly(payload)?;
                Ok(Self::Eip4844(SignedTxEip4844::decode_strict(
                    &rlp::Rlp::new(payload),
                )?))
            }
            eip7702::TYPE_BYTE => {
                check_covers_exactly(payload)?;
                Ok(Self::Eip7702(SignedTxEip7702::decode_strict(
                    &rlp::Rlp::new(payload),
                )?))
            }
            0x00..=0x7f => Err(TxDecodeError::UnknownTxType(first)),
            0x80..=0xbf => Err(TxDecodeError::InvalidEnvelopePrefix(first)),
            0xc0..=0xfe => {
                check_covers_exactly(bytes)?;
                Ok(Self::Legacy(SignedTxLegacy::decode_strict(
                    &rlp::Rlp::new(bytes),
                )?))
            }
            0xff => Err(TxDecodeError::ReservedSentinel),
        }
    }

    /// Writes this transaction's block-body form straight into `stream`.
    ///
    /// The form a body is built from, and the reason it takes a stream rather than returning bytes: a
    /// legacy transaction is written directly, with nothing allocated in between, and a typed one needs
    /// its complete envelope somewhere before it can be wrapped in a byte string. `scratch` is
    /// initialised only for that typed case, then cleared and reused for every following typed
    /// transaction in the body.
    pub(crate) fn append_block_item(
        &self,
        stream: &mut rlp::RlpStream,
        scratch: &mut Option<rlp::RlpStream>,
    ) {
        // A legacy transaction *is* an RLP list, so it goes in as one and needs no detour.
        if let Self::Legacy(tx) = self {
            stream.append(tx);
            return;
        }
        let envelope_stream = scratch.get_or_insert_with(rlp::RlpStream::new);
        let envelope = self.encode_2718_in(envelope_stream);
        // A typed envelope is already contiguous in the scratch buffer. `append_iter` writes the RLP
        // string header and payload directly into the surrounding block stream without collecting an
        // intermediate envelope or length buffer.
        stream.append_iter(envelope.iter().copied());
    }

    /// Decodes one item of a block body's transaction list, accepting a bare RLP list or a
    /// string-wrapped EIP-2718 envelope.
    ///
    /// The two forms are **exclusive**: a bare list is legacy, a byte string is typed. A legacy
    /// transaction wrapped in a byte string decodes to the same transaction as the bare form, so
    /// accepting it would give one block two valid encodings.
    ///
    /// `rlp` must cover exactly one item, and that is enforced here rather than assumed of the
    /// caller. Inside the block decoder it holds already — `Rlp::at` trims each item to its own
    /// bytes — but this is a public entry point, and unwrapping a byte string reads only the string's
    /// payload, so without the check a caller passing `item ‖ trailing` would have the trailing bytes
    /// silently dropped for a typed transaction while a legacy one rejected them.
    ///
    /// # Errors
    /// [`TxDecodeError`] as [`Self::decode_2718`], plus [`TxDecodeError::LegacyInTypedBlockItem`] if a
    /// byte-string item wraps a bare legacy RLP list rather than an EIP-2718 envelope, and
    /// [`TxDecodeError::Rlp`] if the item is neither an RLP list nor a byte string, or does not cover
    /// `rlp` exactly — the two ways it can miss are named apart, `RlpIsTooShort` for an item declaring
    /// more bytes than the buffer holds and `RlpIsTooBig` for bytes past its end.
    pub fn decode_block_item(rlp: &rlp::Rlp<'_>) -> Result<Self, TxDecodeError> {
        let raw = rlp.as_raw();
        check_covers_exactly(raw)?;
        if rlp.is_list() {
            // Legacy: the item *is* the transaction's RLP list.
            return Self::decode_2718(raw);
        }
        // Typed: unwrap the byte string to get the 2718 envelope. Borrowed, not copied — the envelope
        // is only read from here on. A wrapped bare legacy list (`0xc0..=0xfe`) is rejected here;
        // `decode_2718` classifies every other leading-byte range, including the `0xff` sentinel.
        let envelope = rlp.data()?;
        let (&first, _) = envelope.split_first().ok_or(TxDecodeError::Empty)?;
        if matches!(first, 0xc0..=0xfe) {
            return Err(TxDecodeError::LegacyInTypedBlockItem);
        }
        Self::decode_2718(envelope)
    }

    /// The sender's signature over [`Self::signature_hash`].
    #[must_use]
    pub const fn signature(&self) -> TxSignature {
        match self {
            Self::Legacy(tx) => tx.signature,
            Self::Eip2930(tx) => tx.signature,
            Self::Eip1559(tx) => tx.signature,
            Self::Eip4844(tx) => tx.signature,
            Self::Eip7702(tx) => tx.signature,
        }
    }

    /// The signature, mutably.
    ///
    /// Changing it changes the sender the transaction recovers to, and nothing here is cached, so the
    /// new signature takes effect immediately — there is no hash to invalidate.
    pub const fn signature_mut(&mut self) -> &mut TxSignature {
        match self {
            Self::Legacy(tx) => &mut tx.signature,
            Self::Eip2930(tx) => &mut tx.signature,
            Self::Eip1559(tx) => &mut tx.signature,
            Self::Eip4844(tx) => &mut tx.signature,
            Self::Eip7702(tx) => &mut tx.signature,
        }
    }

    /// The bytes the sender signed: the transaction encoded without its signature.
    ///
    /// Total. The preimage differs from the envelope in its tail, and for a legacy transaction also
    /// in its length — six fields or nine, chosen by the chain id the type carries.
    #[must_use]
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut stream = rlp::RlpStream::new();
        self.append_signing_preimage(&mut stream);
        stream.out().to_vec()
    }

    /// Writes the signing preimage into `stream`, clearing it first.
    ///
    /// The form to use over a whole block: one stream serves every transaction and retains its backing
    /// capacity. A typed preimage writes its type byte and field list into that same storage, rather
    /// than materialising the list and then copying it into a second prefixed buffer.
    pub(crate) fn append_signing_preimage(&self, stream: &mut rlp::RlpStream) {
        match self {
            Self::Legacy(tx) => tx.tx.append_signing_preimage(stream),
            Self::Eip2930(tx) => tx.tx.append_signing_preimage(stream),
            Self::Eip1559(tx) => tx.tx.append_signing_preimage(stream),
            Self::Eip4844(tx) => tx.tx.append_signing_preimage(stream),
            Self::Eip7702(tx) => tx.tx.append_signing_preimage(stream),
        }
    }

    /// The hash the sender signed, using `stream` as the buffer.
    ///
    /// [`Self::signature_hash`] with the allocation hoisted out of the call, for a caller walking a
    /// block's transactions.
    ///
    /// # Panics
    /// Panics if an internal signing-preimage encoder leaves its unbounded RLP list unfinished.
    #[must_use]
    pub(crate) fn signature_hash_in(&self, stream: &mut rlp::RlpStream) -> H256 {
        self.append_signing_preimage(stream);
        // `as_raw()` skips `RlpStream::out()`'s completion check; fail closed before sender recovery
        // can hash a signing preimage whose unbounded list was not finalized.
        assert!(
            stream.is_finished(),
            "transaction signing preimage left an open list"
        );
        keccak256(stream.as_raw())
    }

    /// The hash the sender signed, from which the sender is recovered.
    #[must_use]
    pub fn signature_hash(&self) -> H256 {
        keccak256(&self.signing_preimage())
    }

    /// The transaction hash: `keccak256` of the EIP-2718 envelope.
    ///
    /// The identifier, not consensus data — no field of a block commits to it, and the transactions
    /// trie commits to the encoding under an index key. Computed on demand rather than cached,
    /// because nothing in this crate asks for it twice.
    #[must_use]
    pub fn tx_hash(&self) -> H256 {
        let mut stream = rlp::RlpStream::new();
        keccak256(self.encode_2718_in(&mut stream))
    }

    /// The EIP-7702 authorization tuples, empty for every other type.
    #[must_use]
    // Not `const`: returning a slice from a `Vec` needs a deref coercion that is const only on some
    // toolchains, and the crate should build on more than the one it pins.
    #[allow(clippy::missing_const_for_fn)]
    pub fn authorization_list(&self) -> &[SignedAuthorization] {
        match self {
            Self::Eip7702(tx) => &tx.tx.authorization_list,
            Self::Legacy(_) | Self::Eip2930(_) | Self::Eip1559(_) | Self::Eip4844(_) => &[],
        }
    }

    /// The execution environment for this transaction, **consuming** it.
    ///
    /// The last use of the consensus form. Everything it was needed for — the transactions root, the
    /// signature hash, the sender — has already happened by the time this is called, so its owned
    /// fields move into the environment instead of being copied.
    ///
    /// `caller` is what verifying the signature established. The EIP-7702 authorities are recovered
    /// here rather than passed in: they are a function of the tuples the transaction carries, so
    /// deriving them keeps the list one-to-one with those tuples, which is what intrinsic gas is
    /// charged against.
    #[must_use]
    pub fn into_tx_env(self, caller: H160) -> TxEnv {
        match self {
            Self::Legacy(tx) => tx.tx.into_tx_env(caller),
            Self::Eip2930(tx) => tx.tx.into_tx_env(caller),
            Self::Eip1559(tx) => tx.tx.into_tx_env(caller),
            Self::Eip4844(tx) => tx.tx.into_tx_env(caller),
            Self::Eip7702(tx) => tx.tx.into_tx_env(caller),
        }
    }
}

/// Requires the leading RLP item to cover `bytes` exactly.
///
/// RLP is self-delimiting, so a decoder that only reads the leading item would accept padded
/// transaction bytes and re-encode them differently — one transaction with two encodings.
///
/// Exactness is asked for as equality, and the two ways it can fail are opposite faults with their
/// own names: a declared payload the buffer does not hold is `RlpIsTooShort`, bytes past the end of
/// the item are `RlpIsTooBig`.
fn check_covers_exactly(bytes: &[u8]) -> Result<(), TxDecodeError> {
    let consumed = rlp_strict::declared_item_len(bytes)?;
    match consumed.cmp(&bytes.len()) {
        // The item declares a payload the buffer does not hold: too few bytes, not too many.
        Ordering::Greater => Err(TxDecodeError::Rlp(rlp::DecoderError::RlpIsTooShort)),
        // The buffer holds bytes past the end of the item.
        Ordering::Less => Err(TxDecodeError::Rlp(rlp::DecoderError::RlpIsTooBig)),
        Ordering::Equal => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::SignedTxEnvelope;
    use crate::rlp_strict::overflowing_header;
    use crate::transaction::TxType;
    use crate::transaction::types::codec::TxDecodeError;
    use hex_literal::hex;
    use primitive_types::{H160, H256};

    fn encode_block_item(tx: &SignedTxEnvelope) -> Vec<u8> {
        let mut stream = rlp::RlpStream::new();
        let mut scratch = None;
        tx.append_block_item(&mut stream, &mut scratch);
        stream.out().to_vec()
    }

    /// The EIP-1559 type byte, for building a typed envelope whose payload is deliberately malformed.
    const TYPE_BYTE_EIP1559: u8 = super::eip1559::TYPE_BYTE;

    /// One raw transaction per type, so the dispatch is covered end to end.
    fn vectors() -> Vec<(TxType, Vec<u8>)> {
        vec![
            (
                TxType::Legacy,
                hex!(
                    "f85f800182520894000000000000000000000000000b9331677e6ebf0a801ca098ff9212"
                    "01554726367d2be8c804a7ff89ccf285ebc57dff8ae4c44b9c19ac4aa01887321be575c8"
                    "095f789dd4c743dfe42c1820f9231f98a962b210e3ac2452a3"
                )
                .to_vec(),
            ),
            (
                TxType::Eip2930,
                hex!(
                    "01f89b01800a8301e974943068947c19dbbc5a170610a69c65e341f0a0b7458080f838f7"
                    "940000000000000000000000000000000000000000e1a000000000000000000000000000"
                    "0000000000000000000000000000000000000001a0712d63f4983ce033255f9adfe3b159"
                    "f465766eac906591091e3ad03ffc06ad16a0078e21a3501b9fc9b9b9e223cc19768be044"
                    "d5c7c6faf1fbc0f5aa4deb325fe9"
                )
                .to_vec(),
            ),
            (
                TxType::Eip1559,
                hex!(
                    "02f8b00142843b9aca008504a817c80082ad62946069a6c32cf691f5982febae4faf8a6f"
                    "3ab2f0f680b844a22cb4650000000000000000000000005eee75727d804a2b13038928d3"
                    "6f8b188945a57a0000000000000000000000000000000000000000000000000000000000"
                    "000000c080a0840cfc572845f5786e702984c2a582528cad4b49b2a10b9db1be7fca9005"
                    "8565a025e7109ceb98168d95b09b18bbf6b685130e0562f233877d492b94eee0c5b6d1"
                )
                .to_vec(),
            ),
            (
                TxType::Eip4844,
                hex!(
                    "03f8a601808007830f424094000f3df6d732807ef1319fb7b8bb8522d0beac0280a00000"
                    "00000000000000000000000000000000000000000000000000000000000cc001e1a00100"
                    "00000000000000000000000000000000000000000000000000000000000001a08cdee4f5"
                    "29448c31aef67fb75346f7e0279e9545da3194191835349e19888b41a013e7d078013af8"
                    "d334a2b09246dad964099443bb85b20d40bb3b08ea3c93229f"
                )
                .to_vec(),
            ),
            (
                TxType::Eip7702,
                hex!(
                    "04f8e101808007830f424094000f3df6d732807ef1319fb7b8bb8522d0beac0280a00000"
                    "00000000000000000000000000000000000000000000000000000000000cc0f85cf85a80"
                    "9400000000000000000000000000000000000000008080a085044e88414585239b3b7b4f"
                    "91c0bc6275ed817b925d973869370ca9b842925aa02e021ec5210eb0cc051524a05e9049"
                    "d6a57acdf0386e3feeae658df6d2a242a980a0f2e0c327202f18c44b074c628433f8d7ed"
                    "09f7fbe180684f1ab6da84b8d94c4aa00c755520f565a678bac8959549dba76a7c212002"
                    "5b53e1565b09845880a66dbf"
                )
                .to_vec(),
            ),
        ]
    }

    /// The property the whole refactor rests on: the typed layer is a lossless middle step.
    #[test]
    fn bytes_to_typed_and_back_is_byte_identical() {
        for (tx_type, raw) in vectors() {
            let envelope = SignedTxEnvelope::decode_2718(&raw).unwrap();
            assert_eq!(envelope.tx_type(), tx_type, "{tx_type:?}");
            assert_eq!(envelope.encode_2718(), raw, "{tx_type:?} typed re-encode");

            // The projection is one-way, so what is checked is that it reports the type it came from
            // — there is no conversion back whose fidelity could be asserted instead.
            assert_eq!(
                envelope.clone().into_tx_env(H160::zero()).tx_type,
                tx_type,
                "{tx_type:?}"
            );
        }
    }

    /// A block-level caller may alternate transaction types and sizes without stale bytes from the
    /// previous envelope surviving `clear()`.
    #[test]
    fn one_scratch_stream_encodes_a_whole_transaction_sequence() {
        let transactions: Vec<_> = vectors()
            .into_iter()
            .map(|(tx_type, raw)| {
                let envelope = SignedTxEnvelope::decode_2718(&raw).unwrap();
                (tx_type, raw, envelope)
            })
            .collect();
        let mut scratch = rlp::RlpStream::new();

        // The forward pass grows the scratch across the fixtures; the reverse pass then makes shorter
        // envelopes follow the largest one, exercising truncation without releasing that capacity.
        for (tx_type, expected, envelope) in transactions.iter().chain(transactions.iter().rev()) {
            assert_eq!(
                envelope.encode_2718_in(&mut scratch),
                expected,
                "{tx_type:?}"
            );
        }
    }

    /// A stream may preserve an existing prefix while exposing only the envelope written after it.
    #[test]
    fn scratch_with_a_nonzero_start_position_returns_only_the_envelope() {
        let prefix = rlp::encode(&"prefix");
        let expected_prefix = prefix.to_vec();
        let mut scratch = rlp::RlpStream::new_with_buffer(prefix);

        for (tx_type, expected, envelope) in vectors().into_iter().map(|(tx_type, raw)| {
            let envelope = SignedTxEnvelope::decode_2718(&raw).unwrap();
            (tx_type, raw, envelope)
        }) {
            assert_eq!(
                envelope.encode_2718_in(&mut scratch),
                expected,
                "{tx_type:?}"
            );
            assert_eq!(
                &scratch.as_raw()[..expected_prefix.len()],
                expected_prefix,
                "{tx_type:?} prefix"
            );
            assert_eq!(
                scratch.as_raw().len(),
                expected_prefix.len() + expected.len(),
                "{tx_type:?} total length"
            );
        }
    }

    /// Body form and 2718 form differ for typed transactions and coincide for legacy ones.
    #[test]
    fn the_block_body_form_wraps_only_typed_transactions() {
        for (tx_type, raw) in vectors() {
            let envelope = SignedTxEnvelope::decode_2718(&raw).unwrap();
            let item = encode_block_item(&envelope);
            if tx_type == TxType::Legacy {
                assert_eq!(item, raw);
            } else {
                assert_ne!(item, raw);
                assert_eq!(rlp::Rlp::new(&item).data().unwrap(), raw.as_slice());
            }
            assert_eq!(
                SignedTxEnvelope::decode_block_item(&rlp::Rlp::new(&item)).unwrap(),
                envelope,
                "{tx_type:?}"
            );
        }
    }

    #[test]
    fn a_legacy_transaction_wrapped_in_a_byte_string_is_rejected() {
        let (_, raw) = vectors().into_iter().next().unwrap();
        let mut stream = rlp::RlpStream::new();
        stream.append(&raw);
        let wrapped = stream.out().to_vec();
        assert_eq!(
            SignedTxEnvelope::decode_block_item(&rlp::Rlp::new(&wrapped)).unwrap_err(),
            TxDecodeError::LegacyInTypedBlockItem
        );
    }

    /// A transaction must occupy its buffer exactly — its hash is `keccak256` of those bytes, so a
    /// padded one would decode and then re-encode to something else. The two directions are opposite
    /// faults and each is named as itself.
    #[test]
    fn a_transaction_must_cover_its_buffer_exactly() {
        for (tx_type, raw) in vectors() {
            let mut padded = raw.clone();
            padded.push(0x00);
            assert_eq!(
                SignedTxEnvelope::decode_2718(&padded).unwrap_err(),
                TxDecodeError::Rlp(rlp::DecoderError::RlpIsTooBig),
                "{tx_type:?} padded"
            );
            assert_eq!(
                SignedTxEnvelope::decode_2718(&raw[..raw.len() - 1]).unwrap_err(),
                TxDecodeError::Rlp(rlp::DecoderError::RlpIsTooShort),
                "{tx_type:?} truncated"
            );
        }
    }

    /// A declared length that overflows `usize` is rejected wherever EIP-2718 permits RLP parsing.
    ///
    /// After a type byte the overflowing list header is always payload. At the envelope boundary its
    /// first byte is `0xff` on a 64-bit target, so EIP-2718 classifies it as the reserved sentinel
    /// before RLP sees it; on a 32-bit zkVM the header starts with `0xfb` and remains a legacy prefix.
    #[test]
    fn a_declared_length_that_overflows_a_usize_is_rejected() {
        let overflowing = overflowing_header(true);
        let mut typed = vec![TYPE_BYTE_EIP1559];
        typed.extend_from_slice(&overflowing);
        assert_eq!(
            SignedTxEnvelope::decode_2718(&typed).unwrap_err(),
            TxDecodeError::Rlp(rlp::DecoderError::RlpInvalidLength),
            "typed payload"
        );

        let expected = if overflowing[0] == 0xff {
            TxDecodeError::ReservedSentinel
        } else {
            TxDecodeError::Rlp(rlp::DecoderError::RlpInvalidLength)
        };
        assert_eq!(
            SignedTxEnvelope::decode_2718(&overflowing).unwrap_err(),
            expected,
            "envelope boundary"
        );
    }

    /// `decode_block_item` establishes the exact-item invariant itself instead of trusting the caller.
    /// Without it the two branches disagree: unwrapping a byte string reads only the string's payload,
    /// so bytes *outside* the wrapper would be dropped for a typed transaction and rejected for a
    /// legacy one — the same buffer accepted or refused depending on the type it carries.
    #[test]
    fn a_block_item_must_cover_its_buffer_exactly_in_both_branches() {
        for (tx_type, raw) in vectors() {
            let envelope = SignedTxEnvelope::decode_2718(&raw).unwrap();
            let item = encode_block_item(&envelope);
            assert_eq!(
                SignedTxEnvelope::decode_block_item(&rlp::Rlp::new(&item)).unwrap(),
                envelope,
                "{tx_type:?}"
            );

            let mut padded = item.clone();
            padded.extend_from_slice(&hex!("deadbeef"));
            assert_eq!(
                SignedTxEnvelope::decode_block_item(&rlp::Rlp::new(&padded)).unwrap_err(),
                TxDecodeError::Rlp(rlp::DecoderError::RlpIsTooBig),
                "{tx_type:?} with bytes after the item"
            );

            // The opposite fault, named apart: the item declares a payload the buffer does not hold.
            assert_eq!(
                SignedTxEnvelope::decode_block_item(&rlp::Rlp::new(&item[..item.len() - 1]))
                    .unwrap_err(),
                TxDecodeError::Rlp(rlp::DecoderError::RlpIsTooShort),
                "{tx_type:?} truncated"
            );
        }
    }

    /// The invariant the check above makes unnecessary to assume: an item taken from a list is already
    /// trimmed to its own bytes, so the block decoder never relied on the caller either.
    #[test]
    fn an_item_taken_from_a_list_is_trimmed_to_itself() {
        let item = encode_block_item(&SignedTxEnvelope::decode_2718(&vectors()[2].1).unwrap());
        let mut list = rlp::RlpStream::new_list(2);
        list.append_raw(&item, 1);
        list.append_raw(&item, 1);
        let bytes = list.out().to_vec();
        let list = rlp::Rlp::new(&bytes);
        for index in 0..2 {
            assert_eq!(list.at(index).unwrap().as_raw().len(), item.len());
        }
    }

    /// Every first-byte class in EIP-2718 is rejected under its own name when it cannot introduce a
    /// transaction: unsupported typed values, the gap before an RLP list, and the reserved sentinel.
    #[test]
    fn envelope_prefix_ranges_are_classified_before_rlp_decoding() {
        assert_eq!(
            SignedTxEnvelope::decode_2718(&[]).unwrap_err(),
            TxDecodeError::Empty
        );

        // `0x00` has no supported typed transaction, and `0x05..=0x7f` are the remainder of the
        // EIP-2718 typed range after the four types this crate implements.
        for first in core::iter::once(0x00).chain(0x05..=0x7f) {
            assert_eq!(
                SignedTxEnvelope::decode_2718(&[first]).unwrap_err(),
                TxDecodeError::UnknownTxType(first),
                "typed-range byte {first:#04x}"
            );
        }

        // These bytes introduce RLP strings, not typed envelopes or the RLP list a legacy
        // transaction must be.
        for first in 0x80..=0xbf {
            assert_eq!(
                SignedTxEnvelope::decode_2718(&[first]).unwrap_err(),
                TxDecodeError::InvalidEnvelopePrefix(first),
                "invalid envelope prefix {first:#04x}"
            );
        }

        assert_eq!(
            SignedTxEnvelope::decode_2718(&[0xff]).unwrap_err(),
            TxDecodeError::ReservedSentinel
        );
    }

    /// Wrapping does not hide EIP-2718's reserved sentinel behind the block-body byte string.
    #[test]
    fn a_wrapped_reserved_sentinel_keeps_its_own_error() {
        let mut stream = rlp::RlpStream::new();
        stream.append(&vec![0xff]);
        let item = stream.out();
        assert_eq!(
            SignedTxEnvelope::decode_block_item(&rlp::Rlp::new(&item)).unwrap_err(),
            TxDecodeError::ReservedSentinel
        );
    }

    /// A real EIP-155 legacy transaction (`v = 37`), the one form `vectors()` does not cover: the
    /// nine-field signing preimage. Its hash is what distinguishes it from the pre-155 form.
    const LEGACY_EIP155: &[u8] = &hex!(
        "f9015482078b8505d21dba0083022ef1947a250d5630b4cf539739df2c5dacb4c659f2488d880c46549a521b13d8b8e47ff36ab50000000000000000000000000000000000000000000066ab5a608bd00a23f2fe000000000000000000000000000000000000000000000000000000000000008000000000000000000000000048c04ed5691981c42154c6167398f95e8f38a7ff00000000000000000000000000000000000000000000000000000000632ceac70000000000000000000000000000000000000000000000000000000000000002000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc20000000000000000000000006c6ee5e31d828de241282b9606c8e98ea48526e225a0c9077369501641a92ef7399ff81c21639ed4fd8fc69cb793cfa1dbfab342e10aa0615facb2f1bcf3274a354cfe384a38d0cc008a11c2dd23a69111bc6930ba27a8"
    );

    /// Independent consensus vectors for the two hashes.
    ///
    /// The round-trip test proves the *envelope bytes*; these prove the two hashes derived from them,
    /// and they are the only checks here that would catch a preimage which re-encodes correctly and
    /// still hashes wrong. The signing preimage in particular cannot be validated by re-encoding at
    /// all — it differs from the envelope in its tail, and for a legacy transaction in its length.
    ///
    /// Every hash was cross-checked by recovering the signer and comparing it with the fixture's
    /// `sender`. `tx_hash` is absent where the fixture did not publish one.
    #[test]
    fn the_two_hashes_match_their_consensus_vectors() {
        let expected: [(TxType, [u8; 32], Option<[u8; 32]>); 5] = [
            (
                TxType::Legacy,
                hex!("9f8e5c24b9b3a0664a9f8b358c07ea710e5a40b82d40abf75f68029708744dda"),
                Some(hex!(
                    "2781a1444a7a4a646bf551f90913054dc47b2f3493d4a82a057445eb9e1c98cf"
                )),
            ),
            (
                TxType::Eip2930,
                hex!("aa9a862c95f3f72aa762fb89951dccb593f1c3078cb258480a78b7728f94fc5b"),
                None,
            ),
            (
                TxType::Eip1559,
                hex!("0d5688ac3897124635b6cf1bc0e29d6dfebceebdc10a54d74f2ef8b56535b682"),
                Some(hex!(
                    "0ec0b6a2df4d87424e5f6ad2a654e27aaeb7dac20ae9e8385cc09087ad532ee0"
                )),
            ),
            (
                TxType::Eip4844,
                hex!("688f454d4448cc14d98f22b6746b360973cfc228844d9716f2e53c5ed11cf80d"),
                Some(hex!(
                    "fdfacacf596fb56f91cac5b5d6f076cba9681e26f05828e51e719693b18f9418"
                )),
            ),
            (
                TxType::Eip7702,
                hex!("304c3e702781b1eb9ec3e70d7f9457d7c8f3f4ce053124149b8e78f0b066c823"),
                None,
            ),
        ];

        for ((tx_type, raw), (expected_type, signature_hash, tx_hash)) in
            vectors().into_iter().zip(expected)
        {
            assert_eq!(tx_type, expected_type, "the vector order must match");
            let envelope = SignedTxEnvelope::decode_2718(&raw).unwrap();
            assert_eq!(
                envelope.signature_hash(),
                H256(signature_hash),
                "{tx_type:?} signature hash"
            );
            if let Some(expected) = tx_hash {
                assert_eq!(envelope.tx_hash(), H256(expected), "{tx_type:?} tx hash");
            }
        }

        // The nine-field legacy preimage, which no other vector exercises.
        let eip155 = SignedTxEnvelope::decode_2718(LEGACY_EIP155).unwrap();
        assert_eq!(
            eip155.signature_hash(),
            H256(hex!(
                "379ff32b417de419215242f8c5c2f7fe533948b45f0dbe842f7300f889b263ef"
            )),
            "EIP-155 legacy signature hash"
        );
        assert_eq!(eip155.encode_2718(), LEGACY_EIP155);
    }
}
