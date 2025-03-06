use blst::{
	blst_bendian_from_fp, blst_fp, blst_fp_from_bendian, blst_p1_affine, blst_p1_affine_in_g1,
	blst_p1_affine_on_curve, blst_scalar, blst_scalar_from_bendian,
};
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
/// Amount used to calculate the multi-scalar-multiplication discount.
const MSM_MULTIPLIER: u64 = 1000;

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
	input.iter().zip(MODULUS_REPR.iter()).any(|(&a, &b)| a < b)
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

/// Extracts a scalar from a 32 byte slice representation, decoding the input as a big endian
/// unsigned integer. If the input is not exactly 32 bytes long, an error is returned.
///
/// From [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537):
/// * A scalar for the multiplication operation is encoded as 32 bytes by performing BigEndian
///   encoding of the corresponding (unsigned) integer.
///
/// We do not check that the scalar is a canonical Fr element, because the EIP specifies:
/// * The corresponding integer is not required to be less than or equal than main subgroup order
///   `q`.
fn extract_scalar_input(input: &[u8]) -> Result<blst_scalar, &'static str> {
	if input.len() != SCALAR_LENGTH {
		return Err(Box::leak(
			format!("Input should be {SCALAR_LENGTH} bytes, was {}", input.len()).into_boxed_str(),
		));
	}

	let mut out = blst_scalar::default();
	// SAFETY: input length is checked previously, out is a blst value.
	unsafe {
		// NOTE: we do not use `blst_scalar_fr_check` here because, from EIP-2537:
		//
		// * The corresponding integer is not required to be less than or equal than main subgroup
		// order `q`.
		blst_scalar_from_bendian(&mut out, input.as_ptr())
	};

	Ok(out)
}

/// Implements the gas schedule for G1/G2 Multiscalar-multiplication assuming 30
/// MGas/second, see also: <https://eips.ethereum.org/EIPS/eip-2537#g1g2-multiexponentiation>
fn msm_required_gas(k: usize, discount_table: &[u16], multiplication_cost: u64) -> u64 {
	if k == 0 {
		return 0;
	}

	let index = core::cmp::min(k - 1, discount_table.len() - 1);
	let discount = discount_table[index] as u64;

	(k as u64 * discount * multiplication_cost) / MSM_MULTIPLIER
}

mod g1 {
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

mod g2 {
	use super::*;
	use blst::{blst_fp2, blst_p2_affine, blst_p2_affine_in_g2, blst_p2_affine_on_curve};

	/// Length of each of the elements in a g2 operation input.
	pub const G2_INPUT_ITEM_LENGTH: usize = 256;

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

pub mod g1_add {
	use super::*;
	use blst::{blst_p1, blst_p1_add_or_double_affine, blst_p1_from_affine, blst_p1_to_affine};

	/// Input length of g1_add operation.
	const INPUT_LENGTH: usize = 256;

	/// G1 addition call expects `256` bytes as an input that is interpreted as byte
	/// concatenation of two G1 points (`128` bytes each).
	/// Output is an encoding of addition operation result - single G1 point (`128`
	/// bytes).
	/// See also: <https://eips.ethereum.org/EIPS/eip-2537#abi-for-g1-addition>
	pub fn g1_add(input: &[u8]) -> Result<Vec<u8>, &'static str> {
		if input.len() != INPUT_LENGTH {
			return Err(Box::leak(
				format!(
					"G1ADD input should be {INPUT_LENGTH} bytes got {}",
					input.len()
				)
				.into_boxed_str(),
			));
		}

		// NB: There is no subgroup check for the G1 addition precompile.
		//
		// We set the subgroup checks here to `false`
		let a_aff = &g1::extract_g1_input(&input[..g1::G1_INPUT_ITEM_LENGTH], false)?;
		let b_aff = &g1::extract_g1_input(&input[g1::G1_INPUT_ITEM_LENGTH..], false)?;

		let mut b = blst_p1::default();
		// SAFETY: b and b_aff are blst values.
		unsafe { blst_p1_from_affine(&mut b, b_aff) };

		let mut p = blst_p1::default();
		// SAFETY: p, b and a_aff are blst values.
		unsafe { blst_p1_add_or_double_affine(&mut p, &b, a_aff) };

		let mut p_aff = blst_p1_affine::default();
		// SAFETY: p_aff and p are blst values.
		unsafe { blst_p1_to_affine(&mut p_aff, &p) };

		Ok(g1::encode_g1_point(&p_aff))
	}
}

pub mod g1_mul {
	use super::*;
	use blst::{blst_p1, blst_p1_from_affine, blst_p1_to_affine, p1_affines};

	/// Input length of g1_mul operation.
	const INPUT_LENGTH: usize = 160;

	/// Base gas fee for BLS12-381 g1_mul operation.
	pub const BASE_GAS_FEE: u64 = 12000;

	/// Discounts table for G1 MSM as a vector of pairs `[k, discount]`.
	const DISCOUNT_TABLE: [u16; 128] = [
		1000, 949, 848, 797, 764, 750, 738, 728, 719, 712, 705, 698, 692, 687, 682, 677, 673, 669,
		665, 661, 658, 654, 651, 648, 645, 642, 640, 637, 635, 632, 630, 627, 625, 623, 621, 619,
		617, 615, 613, 611, 609, 608, 606, 604, 603, 601, 599, 598, 596, 595, 593, 592, 591, 589,
		588, 586, 585, 584, 582, 581, 580, 579, 577, 576, 575, 574, 573, 572, 570, 569, 568, 567,
		566, 565, 564, 563, 562, 561, 560, 559, 558, 557, 556, 555, 554, 553, 552, 551, 550, 549,
		548, 547, 547, 546, 545, 544, 543, 542, 541, 540, 540, 539, 538, 537, 536, 536, 535, 534,
		533, 532, 532, 531, 530, 529, 528, 528, 527, 526, 525, 525, 524, 523, 522, 522, 521, 520,
		520, 519,
	];

	/// Implements EIP-2537 G1MSM precompile.
	/// G1 multi-scalar-multiplication call expects `160*k` bytes as an input that is interpreted
	/// as byte concatenation of `k` slices each of them being a byte concatenation
	/// of encoding of G1 point (`128` bytes) and encoding of a scalar value (`32`
	/// bytes).
	/// Output is an encoding of multi-scalar-multiplication operation result - single G1
	/// point (`128` bytes).
	/// See also: <https://eips.ethereum.org/EIPS/eip-2537#abi-for-g1-multiexponentiation>
	pub fn g1_mul(input: &[u8]) -> Result<Vec<u8>, &'static str> {
		if input.is_empty() || input.len() % INPUT_LENGTH != 0 {
			return Err(Box::leak(
				format!(
					"G1MSM input length should be multiple of {INPUT_LENGTH}, was {}",
					input.len()
				)
				.into_boxed_str(),
			));
		}

		let k = input.len() / INPUT_LENGTH;
		let mut g1_points: Vec<blst_p1> = Vec::with_capacity(k);
		let mut scalars: Vec<u8> = Vec::with_capacity(k * SCALAR_LENGTH);
		for i in 0..k {
			let slice = &input[i * INPUT_LENGTH..i * INPUT_LENGTH + g1::G1_INPUT_ITEM_LENGTH];

			// BLST batch API for p1_affines blows up when you pass it a point at infinity, so we must
			// filter points at infinity (and their corresponding scalars) from the input.
			if slice.iter().all(|i| *i == 0) {
				continue;
			}

			// NB: Scalar multiplications, MSMs and pairings MUST perform a subgroup check.
			//
			// So we set the subgroup_check flag to `true`
			let p0_aff = &g1::extract_g1_input(slice, true)?;

			let mut p0 = blst_p1::default();
			// SAFETY: p0 and p0_aff are blst values.
			unsafe { blst_p1_from_affine(&mut p0, p0_aff) };
			g1_points.push(p0);

			scalars.extend_from_slice(
				&extract_scalar_input(
					&input[i * INPUT_LENGTH + g1::G1_INPUT_ITEM_LENGTH
						..i * INPUT_LENGTH + g1::G1_INPUT_ITEM_LENGTH + SCALAR_LENGTH],
				)?
				.b,
			);
		}

		// return infinity point if all points are infinity
		if g1_points.is_empty() {
			return Ok([0; 128].into());
		}

		let points = p1_affines::from(&g1_points);
		let multiexp = points.mult(&scalars, NBITS);

		let mut multiexp_aff = blst_p1_affine::default();
		// SAFETY: multiexp_aff and multiexp are blst values.
		unsafe { blst_p1_to_affine(&mut multiexp_aff, &multiexp) };

		Ok(g1::encode_g1_point(&multiexp_aff))
	}

	/// G1MSM required gas
	pub fn required_gas(input: &[u8]) -> u64 {
		let k = input.len() / INPUT_LENGTH;
		msm_required_gas(k, &DISCOUNT_TABLE, BASE_GAS_FEE)
	}
}

pub mod g2_add {
	use super::*;
	use blst::{
		blst_p2, blst_p2_add_or_double_affine, blst_p2_affine, blst_p2_from_affine,
		blst_p2_to_affine,
	};

	/// Input length of g2_add operation.
	const INPUT_LENGTH: usize = 512;

	/// G2 addition call expects `512` bytes as an input that is interpreted as byte
	/// concatenation of two G2 points (`256` bytes each).
	///
	/// Output is an encoding of addition operation result - single G2 point (`256`
	/// bytes).
	/// See also <https://eips.ethereum.org/EIPS/eip-2537#abi-for-g2-addition>
	pub fn g2_add(input: &[u8]) -> Result<Vec<u8>, &'static str> {
		if input.len() != INPUT_LENGTH {
			return Err(Box::leak(
				format!(
					"G2ADD input should be {INPUT_LENGTH} bytes, was {}",
					input.len()
				)
				.into_boxed_str(),
			));
		}

		// NB: There is no subgroup check for the G2 addition precompile.
		//
		// So we set the subgroup checks here to `false`
		let a_aff = &g2::extract_g2_input(&input[..g2::G2_INPUT_ITEM_LENGTH], false)?;
		let b_aff = &g2::extract_g2_input(&input[g2::G2_INPUT_ITEM_LENGTH..], false)?;

		let mut b = blst_p2::default();
		// SAFETY: b and b_aff are blst values.
		unsafe { blst_p2_from_affine(&mut b, b_aff) };

		let mut p = blst_p2::default();
		// SAFETY: p, b and a_aff are blst values.
		unsafe { blst_p2_add_or_double_affine(&mut p, &b, a_aff) };

		let mut p_aff = blst_p2_affine::default();
		// SAFETY: p_aff and p are blst values.
		unsafe { blst_p2_to_affine(&mut p_aff, &p) };

		Ok(g2::encode_g2_point(&p_aff))
	}
}

pub mod g2_mul {
	use super::*;
	use blst::{blst_p2, blst_p2_affine, blst_p2_from_affine, blst_p2_to_affine, p2_affines};

	/// Base gas fee for BLS12-381 g2_mul operation.
	pub const BASE_GAS_FEE: u64 = 22500;

	/// Input length of g2_mul operation.
	pub const INPUT_LENGTH: usize = 288;

	// Discounts table for G2 MSM as a vector of pairs `[k, discount]`:
	pub static DISCOUNT_TABLE: [u16; 128] = [
		1000, 1000, 923, 884, 855, 832, 812, 796, 782, 770, 759, 749, 740, 732, 724, 717, 711, 704,
		699, 693, 688, 683, 679, 674, 670, 666, 663, 659, 655, 652, 649, 646, 643, 640, 637, 634,
		632, 629, 627, 624, 622, 620, 618, 615, 613, 611, 609, 607, 606, 604, 602, 600, 598, 597,
		595, 593, 592, 590, 589, 587, 586, 584, 583, 582, 580, 579, 578, 576, 575, 574, 573, 571,
		570, 569, 568, 567, 566, 565, 563, 562, 561, 560, 559, 558, 557, 556, 555, 554, 553, 552,
		552, 551, 550, 549, 548, 547, 546, 545, 545, 544, 543, 542, 541, 541, 540, 539, 538, 537,
		537, 536, 535, 535, 534, 533, 532, 532, 531, 530, 530, 529, 528, 528, 527, 526, 526, 525,
		524, 524,
	];

	/// Implements EIP-2537 G2MSM precompile.
	/// G2 multi-scalar-multiplication call expects `288*k` bytes as an input that is interpreted
	/// as byte concatenation of `k` slices each of them being a byte concatenation
	/// of encoding of G2 point (`256` bytes) and encoding of a scalar value (`32`
	/// bytes).
	/// Output is an encoding of multi-scalar-multiplication operation result - single G2
	/// point (`256` bytes).
	/// See also: <https://eips.ethereum.org/EIPS/eip-2537#abi-for-g2-multiexponentiation>
	pub fn g2_mul(input: &[u8]) -> Result<Vec<u8>, &'static str> {
		let input_len = input.len();
		if input_len == 0 || input_len % INPUT_LENGTH != 0 {
			return Err(Box::leak(
				format!(
					"G2MSM input length should be multiple of {}, was {}",
					INPUT_LENGTH, input_len
				)
				.into_boxed_str(),
			));
		}

		let k = input_len / INPUT_LENGTH;
		let mut g2_points: Vec<blst_p2> = Vec::with_capacity(k);
		let mut scalars: Vec<u8> = Vec::with_capacity(k * SCALAR_LENGTH);
		for i in 0..k {
			let slice = &input[i * INPUT_LENGTH..i * INPUT_LENGTH + g2::G2_INPUT_ITEM_LENGTH];
			// BLST batch API for p2_affines blows up when you pass it a point at infinity, so we must
			// filter points at infinity (and their corresponding scalars) from the input.
			if slice.iter().all(|i| *i == 0) {
				continue;
			}

			// NB: Scalar multiplications, MSMs and pairings MUST perform a subgroup check.
			//
			// So we set the subgroup_check flag to `true`
			let p0_aff = &g2::extract_g2_input(slice, true)?;

			let mut p0 = blst_p2::default();
			// SAFETY: p0 and p0_aff are blst values.
			unsafe { blst_p2_from_affine(&mut p0, p0_aff) };

			g2_points.push(p0);

			scalars.extend_from_slice(
				&extract_scalar_input(
					&input[i * INPUT_LENGTH + g2::G2_INPUT_ITEM_LENGTH
						..i * INPUT_LENGTH + g2::G2_INPUT_ITEM_LENGTH + SCALAR_LENGTH],
				)?
				.b,
			);
		}

		// return infinity point if all points are infinity
		if g2_points.is_empty() {
			return Ok([0; 256].into());
		}

		let points = p2_affines::from(&g2_points);
		let multiexp = points.mult(&scalars, NBITS);

		let mut multiexp_aff = blst_p2_affine::default();
		// SAFETY: multiexp_aff and multiexp are blst values.
		unsafe { blst_p2_to_affine(&mut multiexp_aff, &multiexp) };

		Ok(g2::encode_g2_point(&multiexp_aff))
	}

	/// G2MSM required gas
	pub fn required_gas(input: &[u8]) -> u64 {
		let k = input.len() / INPUT_LENGTH;
		msm_required_gas(k, &DISCOUNT_TABLE, BASE_GAS_FEE)
	}
}

pub mod pairing {
	use super::*;
	use blst::{blst_final_exp, blst_fp12, blst_fp12_is_one, blst_fp12_mul, blst_miller_loop};

	/// Multiplier gas fee for BLS12-381 pairing operation.
	const PAIRING_MULTIPLIER_BASE: u64 = 32600;
	/// Offset gas fee for BLS12-381 pairing operation.
	const PAIRING_OFFSET_BASE: u64 = 37700;
	/// Input length of pairing operation.
	const INPUT_LENGTH: usize = 384;

	/// Pairing call expects 384*k (k being a positive integer) bytes as an inputs
	/// that is interpreted as byte concatenation of k slices. Each slice has the
	/// following structure:
	///    * 128 bytes of G1 point encoding
	///    * 256 bytes of G2 point encoding
	///
	/// Each point is expected to be in the subgroup of order q.
	/// Output is 32 bytes where first 31 bytes are equal to 0x00 and the last byte
	/// is 0x01 if pairing result is equal to the multiplicative identity in a pairing
	/// target field and 0x00 otherwise.
	///
	/// See also: <https://eips.ethereum.org/EIPS/eip-2537#abi-for-pairing>
	pub fn pairing(input: &[u8]) -> Result<Vec<u8>, &'static str> {
		let input_len = input.len();
		if input_len == 0 || input_len % INPUT_LENGTH != 0 {
			return Err(Box::leak(
				format!(
					"Pairing input length should be multiple of {INPUT_LENGTH}, was {input_len}"
				)
				.into_boxed_str(),
			));
		}

		let k = input_len / INPUT_LENGTH;
		// Accumulator for the fp12 multiplications of the miller loops.
		let mut acc = blst_fp12::default();
		for i in 0..k {
			// NB: Scalar multiplications, MSMs and pairings MUST perform a subgroup check.
			//
			// So we set the subgroup_check flag to `true`
			let p1_aff = &g1::extract_g1_input(
				&input[i * INPUT_LENGTH..i * INPUT_LENGTH + g1::G1_INPUT_ITEM_LENGTH],
				true,
			)?;

			// NB: Scalar multiplications, MSMs and pairings MUST perform a subgroup check.
			//
			// So we set the subgroup_check flag to `true`
			let p2_aff = &g2::extract_g2_input(
				&input[i * INPUT_LENGTH + g1::G1_INPUT_ITEM_LENGTH
					..i * INPUT_LENGTH + g1::G1_INPUT_ITEM_LENGTH + g2::G2_INPUT_ITEM_LENGTH],
				true,
			)?;

			if i > 0 {
				// After the first slice (i>0) we use cur_ml to store the current
				// miller loop and accumulate with the previous results using a fp12
				// multiplication.
				let mut cur_ml = blst_fp12::default();
				let mut res = blst_fp12::default();
				// SAFETY: res, acc, cur_ml, p1_aff and p2_aff are blst values.
				unsafe {
					blst_miller_loop(&mut cur_ml, p2_aff, p1_aff);
					blst_fp12_mul(&mut res, &acc, &cur_ml);
				}
				acc = res;
			} else {
				// On the first slice (i==0) there is no previous results and no need
				// to accumulate.
				// SAFETY: acc, p1_aff and p2_aff are blst values.
				unsafe {
					blst_miller_loop(&mut acc, p2_aff, p1_aff);
				}
			}
		}

		// SAFETY: ret and acc are blst values.
		let mut ret = blst_fp12::default();
		unsafe {
			blst_final_exp(&mut ret, &acc);
		}

		let mut result: u8 = 0;
		// SAFETY: ret is a blst value.
		unsafe {
			if blst_fp12_is_one(&ret) {
				result = 1;
			}
		}
		let mut out = [0u8; 32];
		out[31] = result;
		Ok(out.into())
	}

	/// Pairing required gas
	pub const fn required_gas(input: &[u8]) -> u64 {
		let k = input.len() / INPUT_LENGTH;
		PAIRING_MULTIPLIER_BASE * k as u64 + PAIRING_OFFSET_BASE
	}
}

pub mod map_fp_to_g1 {
	use super::*;
	use blst::{blst_map_to_g1, blst_p1, blst_p1_to_affine};

	/// Field-to-curve call expects 64 bytes as an input that is interpreted as an
	/// element of Fp. Output of this call is 128 bytes and is an encoded G1 point.
	/// See also: <https://eips.ethereum.org/EIPS/eip-2537#abi-for-mapping-fp-element-to-g1-point>
	pub fn map_fp_to_g1(input: &[u8]) -> Result<Vec<u8>, &'static str> {
		if input.len() != PADDED_FP_LENGTH {
			return Err(Box::leak(
				format!(
					"MAP_FP_TO_G1 input should be {PADDED_FP_LENGTH} bytes, was {}",
					input.len()
				)
				.into_boxed_str(),
			));
		}

		let input_p0 = remove_padding(input)?;
		let fp = fp_from_bendian(input_p0)?;

		let mut p = blst_p1::default();
		// SAFETY: p and fp are blst values.
		// third argument is unused if null.
		unsafe { blst_map_to_g1(&mut p, &fp, core::ptr::null()) };

		let mut p_aff = blst_p1_affine::default();
		// SAFETY: p_aff and p are blst values.
		unsafe { blst_p1_to_affine(&mut p_aff, &p) };

		Ok(g1::encode_g1_point(&p_aff))
	}
}

pub mod map_fp2_to_g2 {
	use super::*;
	use crate::bls::g2::check_canonical_fp2;
	use blst::{blst_map_to_g2, blst_p2, blst_p2_affine, blst_p2_to_affine};

	/// Field-to-curve call expects 128 bytes as an input that is interpreted as
	/// an element of Fp2. Output of this call is 256 bytes and is an encoded G2
	/// point.
	/// See also: <https://eips.ethereum.org/EIPS/eip-2537#abi-for-mapping-fp2-element-to-g2-point>
	pub fn map_fp2_to_g2(input: &[u8]) -> Result<Vec<u8>, &'static str> {
		if input.len() != PADDED_FP2_LENGTH {
			return Err(Box::leak(
				format!(
					"MAP_FP2_TO_G2 input should be {PADDED_FP2_LENGTH} bytes, was {}",
					input.len()
				)
				.into_boxed_str(),
			));
		}

		let input_p0_x = remove_padding(&input[..PADDED_FP_LENGTH])?;
		let input_p0_y = remove_padding(&input[PADDED_FP_LENGTH..PADDED_FP2_LENGTH])?;
		let fp2 = check_canonical_fp2(input_p0_x, input_p0_y)?;

		let mut p = blst_p2::default();
		// SAFETY: p and fp2 are blst values.
		// third argument is unused if null.
		unsafe { blst_map_to_g2(&mut p, &fp2, core::ptr::null()) };

		let mut p_aff = blst_p2_affine::default();
		// SAFETY: p_aff and p are blst values.
		unsafe { blst_p2_to_affine(&mut p_aff, &p) };

		Ok(g2::encode_g2_point(&p_aff))
	}
}
