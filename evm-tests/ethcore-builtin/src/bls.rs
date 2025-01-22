#![allow(dead_code)]
use blst::{blst_bendian_from_fp, blst_fp};

/// Number of bits used in the BLS12-381 curve finite field elements.
const NBITS: usize = 256;
/// Finite field element input length.
const FP_LENGTH: usize = 48;
/// Finite field element padded input length.
const PADDED_FP_LENGTH: usize = 64;
/// Quadratic extension of finite field element input length.
const PADDED_FP2_LENGTH: usize = 128;
/// Input elements padding length.
const PADDING_LENGTH: usize = 16;
/// Scalar length.
const SCALAR_LENGTH: usize = 32;
// Big-endian non-Montgomery form.
const MODULUS_REPR: [u8; 48] = [
	0x1a, 0x01, 0x11, 0xea, 0x39, 0x7f, 0xe6, 0x9a, 0x4b, 0x1b, 0xa7, 0xb6, 0x43, 0x4b, 0xac, 0xd7,
	0x64, 0x77, 0x4b, 0x84, 0xf3, 0x85, 0x12, 0xbf, 0x67, 0x30, 0xd2, 0xa0, 0xf6, 0xb0, 0xf6, 0x24,
	0x1e, 0xab, 0xff, 0xfe, 0xb1, 0x53, 0xff, 0xff, 0xb9, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xaa, 0xab,
];

/// BLS Encodes a single finite field element into byte slice with padding.
pub fn x(out: &mut [u8], input: *const blst_fp) {
	if out.len() != PADDED_FP_LENGTH {
		return;
	}
	let (padding, rest) = out.split_at_mut(PADDING_LENGTH);
	padding.fill(0);
	unsafe { blst_bendian_from_fp(rest.as_mut_ptr(), input) };
}
