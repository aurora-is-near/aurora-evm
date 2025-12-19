//! EIP-7623 from Prague hard fork

/// The standard cost of calldata token.
pub const STANDARD_TOKEN_COST: usize = 4;
/// The cost of a non-zero byte in calldata adjusted by [EIP-2028](https://eips.ethereum.org/EIPS/eip-2028).
pub const NON_ZERO_BYTE_DATA_COST: usize = 16;
/// The multiplier for a non zero byte in calldata adjusted by [EIP-2028](https://eips.ethereum.org/EIPS/eip-2028).
pub const NON_ZERO_BYTE_MULTIPLIER: usize = NON_ZERO_BYTE_DATA_COST / STANDARD_TOKEN_COST;
// The cost floor per token
pub const TOTAL_COST_FLOOR_PER_TOKEN: u64 = 10;

/// Retrieve the total number of tokens in calldata.
#[must_use]
pub fn get_tokens_in_calldata(input: &[u8]) -> u64 {
    let zero_data_len = bytecount::count(input, 0);
    let non_zero_data_len = input.len() - zero_data_len;
    u64::try_from(zero_data_len + non_zero_data_len * NON_ZERO_BYTE_MULTIPLIER).unwrap()
}

/// Calculate the transaction cost floor as specified in EIP-7623.
#[must_use]
pub const fn calc_tx_floor_cost(tokens_in_calldata: u64) -> u64 {
    tokens_in_calldata * TOTAL_COST_FLOOR_PER_TOKEN + 21_000
}
