#![allow(dead_code)]

use blst::{
	blst_bendian_from_fp, blst_fp, blst_fp_from_bendian, blst_p1_affine, blst_p1_affine_in_g1,
	blst_p1_affine_on_curve,
};
use std::cmp::Ordering;
use std::convert::TryInto;

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
fn fp_to_bytes(out: &mut [u8], input: *const blst_fp) {
	if out.len() != PADDED_FP_LENGTH {
		return;
	}
	let (padding, rest) = out.split_at_mut(PADDING_LENGTH);
	padding.fill(0);
	unsafe { blst_bendian_from_fp(rest.as_mut_ptr(), input) };
}

/// Checks if the input is a valid big-endian representation of a field element.
fn is_valid_be(input: &[u8; 48]) -> bool {
	for (i, modul) in input.iter().zip(MODULUS_REPR.iter()) {
		match i.cmp(modul) {
			Ordering::Greater => return false,
			Ordering::Less => return true,
			Ordering::Equal => continue,
		}
	}
	// false if matching the modulus
	false
}

/// Checks whether or not the input represents a canonical field element, returning the field
/// element if successful.
fn fp_from_bendian(input: &[u8; 48]) -> Result<blst_fp, &'static str> {
	if !is_valid_be(input) {
		return Err("non-canonical fp value");
	}
	let mut fp = blst_fp::default();
	// SAFETY: input has fixed length, and fp is a blst value.
	unsafe {
		// This performs the check for canonical field elements
		blst_fp_from_bendian(&mut fp, input.as_ptr());
	}

	Ok(fp)
}

/// Removes zeros with which the precompile inputs are left padded to 64 bytes.
fn remove_padding(input: &[u8]) -> Result<&[u8; FP_LENGTH], &'static str> {
	if input.len() != PADDED_FP_LENGTH {
		return Err(Box::leak(
			format!(
				"Padded input should be {PADDED_FP_LENGTH} bytes, was {}",
				input.len()
			)
			.into_boxed_str(),
		));
	}
	let (padding, unpadded) = input.split_at(PADDING_LENGTH);
	if !padding.iter().all(|&x| x == 0) {
		return Err(Box::leak(
			format!("{PADDING_LENGTH} top bytes of input are not zero").into_boxed_str(),
		));
	}
	Ok(unpadded.try_into().unwrap())
}

pub mod g1 {
	use super::*;

	/// Length of each of the elements in a g1 operation input.
	pub const G1_INPUT_ITEM_LENGTH: usize = 128;

	/// Output length of a g1 operation.
	const G1_OUTPUT_LENGTH: usize = 128;

	/// Encodes a G1 point in affine format into byte slice with padded elements.
	pub fn encode_g1_point(input: *const blst_p1_affine) -> Vec<u8> {
		let mut out = vec![0u8; G1_OUTPUT_LENGTH];
		// SAFETY: out comes from fixed length array, input is a blst value.
		unsafe {
			fp_to_bytes(&mut out[..PADDED_FP_LENGTH], &(*input).x);
			fp_to_bytes(&mut out[PADDED_FP_LENGTH..], &(*input).y);
		}
		out
	}

	/// Returns a `blst_p1_affine` from the provided byte slices, which represent the x and y
	/// affine coordinates of the point.
	///
	/// If the x or y coordinate do not represent a canonical field element, an error is returned.
	///
	/// See [fp_from_bendian] for more information.
	pub fn decode_and_check_g1(
		p0_x: &[u8; 48],
		p0_y: &[u8; 48],
	) -> Result<blst_p1_affine, &'static str> {
		let out = blst_p1_affine {
			x: fp_from_bendian(p0_x)?,
			y: fp_from_bendian(p0_y)?,
		};

		Ok(out)
	}

	/// Extracts a G1 point in Affine format from a 128 byte slice representation.
	///
	/// NOTE: This function will perform a G1 subgroup check if `subgroup_check` is set to `true`.
	pub fn extract_g1_input(
		input: &[u8],
		subgroup_check: bool,
	) -> Result<blst_p1_affine, &'static str> {
		if input.len() != G1_INPUT_ITEM_LENGTH {
			return Err(Box::leak(
				format!(
					"Input should be {G1_INPUT_ITEM_LENGTH} bytes, was {}",
					input.len()
				)
				.into_boxed_str(),
			));
		}

		let input_p0_x = remove_padding(&input[..PADDED_FP_LENGTH])?;
		let input_p0_y = remove_padding(&input[PADDED_FP_LENGTH..G1_INPUT_ITEM_LENGTH])?;
		let out = decode_and_check_g1(input_p0_x, input_p0_y)?;

		if subgroup_check {
			// NB: Subgroup checks
			//
			// Scalar multiplications, MSMs and pairings MUST perform a subgroup check.
			//
			// Implementations SHOULD use the optimized subgroup check method:
			//
			// https://eips.ethereum.org/assets/eip-2537/fast_subgroup_checks
			//
			// On any input that fail the subgroup check, the precompile MUST return an error.
			//
			// As endomorphism acceleration requires input on the correct subgroup, implementers MAY
			// use endomorphism acceleration.
			if unsafe { !blst_p1_affine_in_g1(&out) } {
				return Err("Element not in G1");
			}
		} else {
			// From EIP-2537:
			//
			// Error cases:
			//
			// * An input is neither a point on the G1 elliptic curve nor the infinity point
			//
			// NB: There is no subgroup check for the G1 addition precompile.
			//
			// We use blst_p1_affine_on_curve instead of blst_p1_affine_in_g1 because the latter performs
			// the subgroup check.
			//
			// SAFETY: out is a blst value.
			if unsafe { !blst_p1_affine_on_curve(&out) } {
				return Err("Element not on G1 curve");
			}
		}

		Ok(out)
	}
}

pub mod g2 {
	use super::*;
	use blst::{blst_fp2, blst_p2_affine, blst_p2_affine_in_g2, blst_p2_affine_on_curve};

	/// Length of each of the elements in a g2 operation input.
	pub(super) const G2_INPUT_ITEM_LENGTH: usize = 256;

	/// Output length of a g2 operation.
	const G2_OUTPUT_LENGTH: usize = 256;

	/// Encodes a G2 point in affine format into byte slice with padded elements.
	pub fn encode_g2_point(input: &blst_p2_affine) -> Vec<u8> {
		let mut out = vec![0u8; G2_OUTPUT_LENGTH];
		fp_to_bytes(&mut out[..PADDED_FP_LENGTH], &input.x.fp[0]);
		fp_to_bytes(
			&mut out[PADDED_FP_LENGTH..2 * PADDED_FP_LENGTH],
			&input.x.fp[1],
		);
		fp_to_bytes(
			&mut out[2 * PADDED_FP_LENGTH..3 * PADDED_FP_LENGTH],
			&input.y.fp[0],
		);
		fp_to_bytes(
			&mut out[3 * PADDED_FP_LENGTH..4 * PADDED_FP_LENGTH],
			&input.y.fp[1],
		);
		out
	}

	/// Convert the following field elements from byte slices into a `blst_p2_affine` point.
	pub fn decode_and_check_g2(
		x1: &[u8; 48],
		x2: &[u8; 48],
		y1: &[u8; 48],
		y2: &[u8; 48],
	) -> Result<blst_p2_affine, &'static str> {
		Ok(blst_p2_affine {
			x: check_canonical_fp2(x1, x2)?,
			y: check_canonical_fp2(y1, y2)?,
		})
	}

	/// Checks whether or not the input represents a canonical fp2 field element, returning the field
	/// element if successful.
	pub fn check_canonical_fp2(
		input_1: &[u8; 48],
		input_2: &[u8; 48],
	) -> Result<blst_fp2, &'static str> {
		let fp_1 = fp_from_bendian(input_1)?;
		let fp_2 = fp_from_bendian(input_2)?;

		let fp2 = blst_fp2 { fp: [fp_1, fp_2] };

		Ok(fp2)
	}

	/// Extracts a G2 point in Affine format from a 256 byte slice representation.
	///
	/// NOTE: This function will perform a G2 subgroup check if `subgroup_check` is set to `true`.
	pub fn extract_g2_input(
		input: &[u8],
		subgroup_check: bool,
	) -> Result<blst_p2_affine, &'static str> {
		if input.len() != G2_INPUT_ITEM_LENGTH {
			return Err(Box::leak(
				format!(
					"Input should be {G2_INPUT_ITEM_LENGTH} bytes, was {}",
					input.len()
				)
				.into_boxed_str(),
			));
		}

		let mut input_fps = [&[0; FP_LENGTH]; 4];
		for i in 0..4 {
			input_fps[i] =
				remove_padding(&input[i * PADDED_FP_LENGTH..(i + 1) * PADDED_FP_LENGTH])?;
		}

		let out = decode_and_check_g2(input_fps[0], input_fps[1], input_fps[2], input_fps[3])?;

		if subgroup_check {
			// NB: Subgroup checks
			//
			// Scalar multiplications, MSMs and pairings MUST perform a subgroup check.
			//
			// Implementations SHOULD use the optimized subgroup check method:
			//
			// https://eips.ethereum.org/assets/eip-2537/fast_subgroup_checks
			//
			// On any input that fail the subgroup check, the precompile MUST return an error.
			//
			// As endomorphism acceleration requires input on the correct subgroup, implementers MAY
			// use endomorphism acceleration.
			if unsafe { !blst_p2_affine_in_g2(&out) } {
				return Err("Element not in G2");
			}
		} else {
			// From EIP-2537:
			//
			// Error cases:
			//
			// * An input is neither a point on the G2 elliptic curve nor the infinity point
			//
			// NB: There is no subgroup check for the G2 addition precompile.
			//
			// We use blst_p2_affine_on_curve instead of blst_p2_affine_in_g2 because the latter performs
			// the subgroup check.
			//
			// SAFETY: out is a blst value.
			if unsafe { !blst_p2_affine_on_curve(&out) } {
				return Err("Element not on G2 curve");
			}
		}

		Ok(out)
	}
}
