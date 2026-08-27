//! Strict RLP guards for untrusted consensus input.
//!
//! The upstream accessors are intentionally lenient in ways this crate cannot accept:
//!
//! - [`rlp::Rlp::item_count`] and [`rlp::Rlp::list_at`] use an iterator whose parse error ends the
//!   walk, so a string can resemble an empty list and a malformed suffix can be hidden.
//! - [`rlp::Rlp::data`] exposes payload bytes without requiring a canonical byte string.
//! - [`rlp::PayloadInfo::total`] adds header and payload lengths without overflow checking.
//!
//! [`checked_len`] verifies a complete list, [`checked_list_at`] applies that check to a nested list,
//! and [`declared_item_len`] computes an item's extent with checked arithmetic. Canonical scalar and
//! fixed-width decoding uses `Rlp::decoder().decode_value`; ordinary decoding remains with `rlp`.

/// Number of items in `rlp`, requiring it to be a list whose items exactly tile its payload.
///
/// The strict replacement for [`rlp::Rlp::item_count`].
///
/// # Errors
/// [`rlp::DecoderError::RlpExpectedToBeList`] if `rlp` is not a list;
/// [`rlp::DecoderError::RlpInconsistentLengthAndData`] if its items do not tile its payload.
pub fn checked_len(rlp: &rlp::Rlp<'_>) -> Result<usize, rlp::DecoderError> {
    if !rlp.is_list() {
        return Err(rlp::DecoderError::RlpExpectedToBeList);
    }
    // This bounded accessor proves the declared payload fits inside `as_raw()`.
    let payload_len = rlp.payload_info()?.value_len;
    let mut covered: usize = 0;
    let mut count: usize = 0;
    // Ordered iteration uses `Rlp`'s offset cache. Both sums are bounded by the validated payload:
    // each item lies inside it, and no RLP item is zero bytes wide.
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
/// # Errors
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
/// Unlike [`rlp::PayloadInfo::total`], this checks the header-plus-payload addition.
///
/// The result is not checked against `bytes.len()`; callers classify truncated, exact and trailing
/// input according to their own error type.
///
/// # Errors
/// [`rlp::DecoderError`] if `bytes` has no readable header;
/// [`rlp::DecoderError::RlpInvalidLength`] if the declared length overflows a `usize`.
pub fn declared_item_len(bytes: &[u8]) -> Result<usize, rlp::DecoderError> {
    let info = rlp::PayloadInfo::from(bytes)?;
    info.header_len
        .checked_add(info.value_len)
        .ok_or(rlp::DecoderError::RlpInvalidLength)
}

/// Builds a long-form RLP header whose declared extent overflows `usize`.
///
/// `list` picks the long-list form (`0xf8..=0xff`) over the long-string form (`0xb8..=0xbf`).
/// Its length-of-length follows the target pointer width so it reaches the overflow on 32-bit zkVMs.
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
        // The malformed item makes the upstream iterator stop and report zero items.
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
        // The helper reports the header claim; callers distinguish truncation from trailing bytes.
        let truncated = hex!("f840010203");
        assert_eq!(declared_item_len(&truncated).unwrap(), 66);
        assert!(declared_item_len(&truncated).unwrap() > truncated.len());
    }

    #[test]
    fn a_declared_length_that_overflows_a_usize_is_rejected_rather_than_summed() {
        // `PayloadInfo::total()` would overflow when adding this header to `usize::MAX`.
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

    /// The vector must reach the addition overflow on both host and zkVM pointer widths.
    #[test]
    fn the_overflow_vector_is_sized_for_this_target() {
        let list = overflowing_header(true);
        assert_eq!(list.len(), 1 + size_of::<usize>());
        assert_eq!(list[0], 0xf7 + u8::try_from(size_of::<usize>()).unwrap());
        assert!(list[1..].iter().all(|byte| *byte == 0xff));
        // Eight length bytes are rejected before the addition on narrower targets.
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
    /// `data()` accepts lists and non-minimal strings that `decode_value` rejects.
    #[test]
    fn rlp_data_is_lenient_where_decode_value_is_not() {
        let borrow = |bytes: &[u8]| Ok::<Vec<u8>, rlp::DecoderError>(bytes.to_vec());

        // A list, whose payload `data()` hands back as though it were a string.
        let list = hex!("c101");
        let rlp = rlp::Rlp::new(&list);
        assert_eq!(rlp.data().unwrap(), hex!("01"));
        assert_eq!(
            rlp.decoder().decode_value(borrow).unwrap_err(),
            rlp::DecoderError::RlpExpectedToBeData
        );

        // The non-minimal encoding of `0x01`: one value must have one encoding, and this is not it.
        let indirect = hex!("8101");
        let rlp = rlp::Rlp::new(&indirect);
        assert_eq!(rlp.data().unwrap(), hex!("01"));
        assert_eq!(
            rlp.decoder().decode_value(borrow).unwrap_err(),
            rlp::DecoderError::RlpInvalidIndirection
        );
    }
}
