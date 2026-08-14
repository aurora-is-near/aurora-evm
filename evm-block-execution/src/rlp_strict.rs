//! Strict RLP boundary helpers for consensus decoding.
//!
//! The upstream `rlp` API exposes two low-level behaviours that are useful in its general-purpose
//! decoding model but do not, by themselves, establish the invariants required at this crate's
//! untrusted input boundary:
//!
//! - [`rlp::Rlp::item_count`] and [`rlp::Rlp::list_at`] rely on a list walk whose parse failure ends
//!   iteration, so they can report a valid prefix as the whole list or treat a byte string as an
//!   empty list;
//! - [`rlp::PayloadInfo::total`] adds header and payload lengths without checked arithmetic and does
//!   not classify how the declared extent relates to the supplied buffer.
//!
//! This module makes those assumptions explicit and fallible: [`checked_len`] and
//! [`checked_list_at`] prove the expected list shape and complete payload coverage, while
//! [`declared_item_len`] computes the encoded extent without overflow and leaves exact/truncated/
//! trailing-buffer classification to the caller. It is not a replacement RLP decoder; after these
//! boundary invariants are established, the crate continues to use `rlp` for ordinary decoding.
//!
//! # A list walk that cannot report a failure
//!
//! Iteration yields `Option`, so a malformed item cannot be an error — the walk just stops. Two
//! kinds of bytes therefore decode successfully that consensus data must never accept:
//!
//! - a **byte string where a list belongs** yields nothing and reads as an empty list, so `list_at`
//!   returns `Ok(vec![])`;
//! - a list whose items cover only a **prefix** of its payload reads as that prefix, and the rest is
//!   hidden: it satisfies every length check and disappears on re-encoding.
//!
//! Neither rejection implies the other — `0x80` tiles trivially yet is not a list, and `0xc3 b9ffff`
//! is a list whose payload holds no item at all — so [`checked_len`] checks both.
//!
//! A list that passes [`checked_len`] *is* a list and its items tile its payload exactly, so the
//! count is complete: the same number `item_count` reports, but proven rather than assumed. From
//! that point `rlp`'s own accessors are safe on that list.
//!
//! The guarantee is **one level deep**. A nested list is a separate claim and is checked where it is
//! read, which is why every list this crate decodes passes through here.
//!
//! The leniency compensated for is itself asserted by the tests below, so an `rlp` that ever becomes
//! strict makes them fail rather than leaving this module silently redundant.
//!
//! # A declared length that is summed without a guard
//!
//! [`rlp::PayloadInfo::total`] adds the header length to the payload length with a plain `+`, and the
//! payload length is decoded from up to `size_of::<usize>()` bytes of the input — so it reaches
//! `usize::MAX` and the sum overflows. [`declared_item_len`] is the guarded form.
//!
//! This one is not a gap in `rlp`: the library guards the same sum with `checked_add` wherever it
//! makes it itself, and its bounded accessor `Rlp::payload_info` does too. `PayloadInfo::total` is a
//! low-level primitive whose contract assumes the bound was already established elsewhere — an
//! assumption that holds nowhere at a decoder's entry point, which is exactly where this crate needs
//! the number.

/// Number of items in `rlp`, requiring it to be a list whose items exactly tile its payload.
///
/// The strict replacement for [`rlp::Rlp::item_count`].
///
/// ## Errors
/// [`rlp::DecoderError::RlpExpectedToBeList`] if `rlp` is not a list;
/// [`rlp::DecoderError::RlpInconsistentLengthAndData`] if its items do not tile its payload.
pub fn checked_len(rlp: &rlp::Rlp<'_>) -> Result<usize, rlp::DecoderError> {
    if !rlp.is_list() {
        return Err(rlp::DecoderError::RlpExpectedToBeList);
    }
    // The bounded accessor, not `PayloadInfo::from`: it establishes `header_len + value_len <=
    // rlp.as_raw().len()`, which is what makes the sum below unable to overflow.
    let payload_len = rlp.payload_info()?.value_len;
    let mut covered: usize = 0;
    let mut count: usize = 0;
    // `at()` resumes from an offset cache when the items are walked in order, so this is one linear
    // pass over the item headers; the items themselves are not decoded.
    //
    // `covered` is summed without a guard because every item's slice lies inside this list's payload,
    // so the total cannot pass `payload_len` — itself bounded by the buffer. `count` is bounded by the
    // same payload, since no item is zero bytes wide.
    for item in rlp {
        covered += item.as_raw().len();
        count += 1;
    }
    if covered == payload_len {
        Ok(count)
    } else {
        Err(rlp::DecoderError::RlpInconsistentLengthAndData)
    }
}

/// Decodes every item of the list at `index`. The strict replacement for [`rlp::Rlp::list_at`].
///
/// ## Errors
/// As [`checked_len`], plus whatever `T::decode` returns.
pub fn checked_list_at<T: rlp::Decodable>(
    rlp: &rlp::Rlp<'_>,
    index: usize,
) -> Result<Vec<T>, rlp::DecoderError> {
    let list = rlp.at(index)?;
    checked_len(&list)?;
    list.as_list()
}

/// Number of bytes the leading RLP item **declares** it occupies, header included.
///
/// The guarded replacement for [`rlp::PayloadInfo::total`], which sums the two lengths with a plain
/// `+`: `value_len` is decoded from up to `size_of::<usize>()` bytes of the input, so it reaches
/// `usize::MAX` and the sum overflows — wrapping where overflow checks are off, panicking where they
/// are on. A header and its length bytes are enough to reach it, so at a decoder's entry point the sum
/// has to be guarded.
///
/// The count is *declared*, not verified against the buffer. Comparing the two belongs to the caller:
/// a declared length above the buffer and one below it are different faults, and only the caller has
/// the vocabulary to name them. Equality is what a caller needing exactness asks for, and it is
/// strictly stronger than the `<= len` that [`rlp::Rlp::payload_info`] would impose here.
///
/// ## Errors
/// [`rlp::DecoderError`] if `bytes` carries no readable header;
/// [`rlp::DecoderError::RlpInvalidLength`] if the declared length overflows a `usize`.
pub fn declared_item_len(bytes: &[u8]) -> Result<usize, rlp::DecoderError> {
    let info = rlp::PayloadInfo::from(bytes)?;
    info.header_len
        .checked_add(info.value_len)
        .ok_or(rlp::DecoderError::RlpInvalidLength)
}

/// A long-form RLP header whose declared payload length overflows a `usize`, and nothing behind it.
///
/// `list` picks the long-list form (`0xf8..=0xff`) over the long-string form (`0xb8..=0xbf`).
///
/// Sized from [`size_of::<usize>`](core::mem::size_of) rather than hardcoded to eight length bytes,
/// because `rlp`'s `decode_usize` rejects more length bytes than a `usize` holds. A hardcoded
/// eight-byte form fails as `RlpIsTooBig` on a 32-bit target — before the sum this exercises is ever
/// attempted — and a zkVM guest is 32-bit, so the hardcoded vector would silently stop testing
/// anything there.
#[cfg(test)]
pub fn overflowing_header(list: bool) -> Vec<u8> {
    let len_of_len = core::mem::size_of::<usize>();
    let indirection = u8::try_from(len_of_len).expect("a pointer is at most 255 bytes wide");
    // `header_len` is `1 + len_of_len` and `value_len` is `usize::MAX`, so their sum leaves the range.
    let mut bytes = vec![if list { 0xf7 } else { 0xb7 } + indirection];
    bytes.extend_from_slice(&vec![0xff; len_of_len]);
    bytes
}

#[cfg(test)]
mod tests {
    use super::{checked_len, checked_list_at, declared_item_len, overflowing_header};
    use hex_literal::hex;

    #[test]
    fn a_genuine_list_is_accepted_with_its_item_count() {
        assert_eq!(checked_len(&rlp::Rlp::new(&hex!("c0"))).unwrap(), 0);
        let three = rlp::encode_list(&[1u8, 2, 3]).to_vec();
        assert_eq!(checked_len(&rlp::Rlp::new(&three)).unwrap(), 3);
    }

    #[test]
    fn a_byte_string_is_not_an_empty_list() {
        for bytes in [
            hex!("80").to_vec(),
            hex!("83aabbcc").to_vec(),
            hex!("05").to_vec(),
        ] {
            assert_eq!(
                checked_len(&rlp::Rlp::new(&bytes)).unwrap_err(),
                rlp::DecoderError::RlpExpectedToBeList,
                "{bytes:02x?}"
            );
        }
    }

    #[test]
    fn a_lists_items_must_tile_its_payload() {
        // A long-string header claiming 65535 bytes with nothing behind it: `payload_info` fails,
        // so `rlp`'s own walk stops there and reports zero items.
        let hiding = hex!("c3b9ffff");
        assert!(rlp::Rlp::new(&hiding).is_list());
        assert_eq!(rlp::Rlp::new(&hiding).item_count().unwrap(), 0);
        assert_eq!(
            checked_len(&rlp::Rlp::new(&hiding)).unwrap_err(),
            rlp::DecoderError::RlpInconsistentLengthAndData
        );
    }

    #[test]
    fn neither_check_implies_the_other() {
        // `0x80` tiles trivially (empty payload, zero items) yet is not a list.
        let empty_string = rlp::Rlp::new(&hex!("80"));
        assert_eq!(empty_string.payload_info().unwrap().value_len, 0);
        assert_eq!(empty_string.iter().count(), 0);
        assert!(checked_len(&empty_string).is_err());
        // `0xc3 b9ffff` is a list, so only the tiling half rejects it.
        let hiding = rlp::Rlp::new(&hex!("c3b9ffff"));
        assert!(hiding.is_list());
        assert!(checked_len(&hiding).is_err());
    }

    #[test]
    fn declared_item_len_is_the_header_plus_the_payload_it_declares() {
        // A single byte is its own item: no header.
        assert_eq!(declared_item_len(&hex!("05")).unwrap(), 1);
        // One header byte plus three of payload.
        assert_eq!(declared_item_len(&hex!("83aabbcc")).unwrap(), 4);
        let three = rlp::encode_list(&[1u8, 2, 3]).to_vec();
        assert_eq!(declared_item_len(&three).unwrap(), three.len());
    }

    #[test]
    fn declared_item_len_reports_the_declared_extent_not_the_buffer() {
        // A long-form header declaring 64 bytes of payload, with three supplied. The number is what
        // the header claims; comparing it with the buffer is the caller's, because the two
        // directions are different faults.
        let truncated = hex!("f840010203");
        assert_eq!(declared_item_len(&truncated).unwrap(), 66);
        assert!(declared_item_len(&truncated).unwrap() > truncated.len());
    }

    #[test]
    fn a_declared_length_that_overflows_a_usize_is_rejected_rather_than_summed() {
        // `value_len` is `usize::MAX`, so `header_len + value_len` leaves the range.
        // `PayloadInfo::total()` wraps here where overflow checks are off and panics where they are
        // on; a header and its length bytes are the whole attack.
        for bytes in [overflowing_header(false), overflowing_header(true)] {
            let info = rlp::PayloadInfo::from(&bytes).unwrap();
            assert_eq!(info.header_len, bytes.len(), "{bytes:02x?}");
            assert_eq!(info.value_len, usize::MAX, "{bytes:02x?}");
            assert!(
                info.value_len > usize::MAX - info.header_len,
                "{bytes:02x?}: the sum must actually overflow, or the test proves nothing"
            );
            assert_eq!(
                declared_item_len(&bytes).unwrap_err(),
                rlp::DecoderError::RlpInvalidLength,
                "{bytes:02x?}"
            );
        }
    }

    /// The vector must overflow on the target actually being built, not only on a 64-bit host: a
    /// hardcoded eight-byte length would be rejected as `RlpIsTooBig` by `decode_usize` on a 32-bit
    /// target and would stop reaching the sum at all.
    #[test]
    fn the_overflow_vector_is_sized_for_this_target() {
        let list = overflowing_header(true);
        assert_eq!(list.len(), 1 + size_of::<usize>());
        assert_eq!(list[0], 0xf7 + u8::try_from(size_of::<usize>()).unwrap());
        assert!(list[1..].iter().all(|byte| *byte == 0xff));
        // Eight length bytes are the wrong vector wherever a `usize` is narrower than eight bytes.
        let hardcoded = hex!("ffffffffffffffffff");
        assert_eq!(
            rlp::PayloadInfo::from(&hardcoded).is_ok(),
            size_of::<usize>() >= 8
        );
    }

    #[test]
    fn declared_item_len_needs_a_readable_header() {
        assert_eq!(
            declared_item_len(&[]).unwrap_err(),
            rlp::DecoderError::RlpIsTooShort
        );
        // A long-form header whose length bytes are missing.
        assert_eq!(
            declared_item_len(&hex!("f8")).unwrap_err(),
            rlp::DecoderError::RlpIsTooShort
        );
    }

    #[test]
    fn checked_list_at_rejects_what_list_at_accepts() {
        // A two-item outer list whose second item is a byte string where a list belongs.
        let mut stream = rlp::RlpStream::new_list(2);
        stream.append(&1u8);
        stream.append(&vec![0xaau8; 3]);
        let bytes = stream.out().to_vec();
        let rlp = rlp::Rlp::new(&bytes);
        // `rlp`'s own accessor calls that an empty list.
        assert_eq!(rlp.list_at::<u8>(1).unwrap(), Vec::<u8>::new());
        assert_eq!(
            checked_list_at::<u8>(&rlp, 1).unwrap_err(),
            rlp::DecoderError::RlpExpectedToBeList
        );
    }
}
