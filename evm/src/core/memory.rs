use super::prelude::*;
use super::utils::USIZE_MAX;
use crate::{ExitError, ExitFatal};
use core::cmp::min;
use core::ops::{BitAnd, Not};
use primitive_types::{H256, U256};

/// A sequential memory. It uses Rust's `Vec` for internal
/// representation.
#[derive(Clone, Debug)]
pub struct Memory {
    /// Memory data
    data: Vec<u8>,
    /// Memory effective length, that changed after resize operations.
    effective_len: usize,
    /// Memory limit
    limit: usize,
}

impl Memory {
    /// Create a new memory with the given limit.
    #[must_use]
    pub const fn new(limit: usize) -> Self {
        Self {
            data: Vec::new(),
            effective_len: 0,
            limit,
        }
    }

    /// Memory limit.
    #[must_use]
    pub const fn limit(&self) -> usize {
        self.limit
    }

    /// Get the length of the current memory range.
    #[must_use]
    // TODO: rust-v1.87 - const fn
    #[allow(clippy::missing_const_for_fn)]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Get the effective length.
    #[must_use]
    pub const fn effective_len(&self) -> usize {
        self.effective_len
    }

    /// Return true if current effective memory range is zero.
    #[must_use]
    // TODO: rust-v1.87 - const fn
    #[allow(clippy::missing_const_for_fn)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return the full memory.
    #[must_use]
    pub const fn data(&self) -> &Vec<u8> {
        &self.data
    }

    /// Resize the memory, making it cover the memory region of `offset..offset + len`,
    /// with 32 bytes as the step. If the length is zero, this function does nothing.
    ///
    /// # Errors
    /// Return `ExitError::InvalidRange` if `offset + len` is overflow.
    pub fn resize_offset(&mut self, offset: usize, len: usize) -> Result<(), ExitError> {
        if len == 0 {
            return Ok(());
        }

        offset
            .checked_add(len)
            .map_or(Err(ExitError::InvalidRange), |end| self.resize_end(end))
    }

    /// Resize the memory, making it cover to `end`, with 32 bytes as the step.
    ///
    /// # Errors
    /// Return `ExitError::InvalidRange` if `end` value is overflow in `next_multiple_of_32` call.
    pub fn resize_end(&mut self, end: usize) -> Result<(), ExitError> {
        if end > self.effective_len {
            let new_end = next_multiple_of_32(end).ok_or(ExitError::InvalidRange)?;
            self.effective_len = new_end;
        }

        Ok(())
    }

    /// Get memory region at given offset.
    ///
    /// ## Panics
    ///
    /// Value of `size` is considered trusted. If they're too large,
    /// the program can run out of memory, or it can overflow.
    #[must_use]
    pub fn get(&self, mut offset: usize, size: usize) -> Vec<u8> {
        if offset > self.data.len() {
            offset = self.data.len();
        }

        let mut end = offset + size;
        if end > self.data.len() {
            end = self.data.len();
        }

        let mut ret = self.data[offset..end].to_vec();
        ret.resize(size, 0);
        ret
    }

    /// Get `H256` value from a specific offset in memory.
    #[must_use]
    pub fn get_h256(&self, offset: usize) -> H256 {
        let mut ret = [0; 32];

        let data_len = self.data.len();
        if offset >= data_len {
            return H256(ret);
        }
        let available_bytes = data_len - offset;
        let count = 32.min(available_bytes);
        ret[..count].copy_from_slice(&self.data[offset..offset + count]);

        H256(ret)
    }

    /// Set memory region at given offset. The offset and value is considered
    /// untrusted.
    ///
    /// # Errors
    /// Return `ExitFatal::NotSupported` if `offset + target_size` is out of memory limit or overflow.
    pub fn set(
        &mut self,
        offset: usize,
        value: &[u8],
        target_size: usize,
    ) -> Result<(), ExitFatal> {
        if target_size == 0 {
            return Ok(());
        }

        let end_offset = match offset.checked_add(target_size) {
            Some(pos) if pos <= self.limit => pos,
            _ => return Err(ExitFatal::NotSupported),
        };

        if self.data.len() < end_offset {
            self.data.resize(end_offset, 0);
        }

        let copy_len = min(value.len(), target_size);
        let dest_slice = &mut self.data[offset..end_offset];
        if copy_len > 0 {
            dest_slice[..copy_len].copy_from_slice(&value[..copy_len]);
        }

        if target_size > copy_len {
            dest_slice[copy_len..].fill(0);
        }

        Ok(())
    }

    /// Copy memory region form `src` to `dst` with length.
    /// `copy_within` uses `memmove` to avoid `DoS` attacks.
    ///
    /// # Errors
    /// Return `ExitFatal::Other`:
    /// - `OverflowOnCopy` if `offset + length` is overflow
    /// - `OutOfGasOnCopy` if `offst_length` out of memory limit
    pub fn copy(
        &mut self,
        src_offset: usize,
        dst_offset: usize,
        length: usize,
    ) -> Result<(), ExitFatal> {
        // If length is zero - do nothing
        if length == 0 {
            return Ok(());
        }

        // Get maximum offset
        let offset = core::cmp::max(src_offset, dst_offset);
        let offset_length = offset
            .checked_add(length)
            .ok_or_else(|| ExitFatal::Other(Cow::from("OverflowOnCopy")))?;
        if offset_length > self.limit {
            return Err(ExitFatal::Other(Cow::from("OutOfGasOnCopy")));
        }

        // Resize data memory
        if self.data.len() < offset_length {
            self.data.resize(offset_length, 0);
        }

        self.data
            .copy_within(src_offset..src_offset + length, dst_offset);
        Ok(())
    }

    /// Copy `data` into the memory, for the given `length`.
    ///
    /// Copies `min(length, available_source_bytes)` from the source `data`
    /// starting at `data_offset`, into `self.data` starting at `memory_offset`.
    /// If `length` is greater than the number of bytes copied from source, the
    /// remaining bytes in the destination range (up to `length`) are filled with zeros.
    ///
    /// # Errors
    /// Returns `ExitFatal::NotSupported` if the destination range `memory_offset..memory_offset + length`
    /// exceeds the memory limit or causes usize overflow.
    pub fn copy_data(
        &mut self,
        memory_offset: usize,
        data_offset: U256,
        length: usize,
        data: &[u8],
    ) -> Result<(), ExitFatal> {
        // 1. Handle zero length copy (no-op)
        if length == 0 {
            return Ok(());
        }

        // 2. Check destination bounds and calculate end offset
        let dest_end_offset = match memory_offset.checked_add(length) {
            Some(pos) if pos <= self.limit => pos,
            _ => return Err(ExitFatal::NotSupported), // Error if overflow or exceeds limit
        };

        // 3. Ensure destination buffer (`self.data`) is large enough
        //    Resize before taking mutable slices.
        if self.data.len() < dest_end_offset {
            self.data.resize(dest_end_offset, 0);
        }

        // 4. Preparing the copy and padding directly into self.data
        // Get the mutable slice of the exact destination region length
        // This is safe because we resized self.data to at least `dest_end_offset`
        let dest_slice = &mut self.data[memory_offset..dest_end_offset];

        // 5. Check source bounds and rethink zero the data slice
        if data_offset > USIZE_MAX {
            dest_slice.fill(0);
            return Ok(());
        }
        let data_offset = data_offset.as_usize();
        if data_offset > data.len() {
            dest_slice.fill(0);
            return Ok(());
        }
        // Calculate how many bytes are available in `data` from `data_offset`
        let actual_len = data.len() - data_offset;
        // Calculate copy length as the minimum of requested length and available length
        let copy_len = min(actual_len, length);
        // Copy data to `dest_slice`
        if copy_len > 0 {
            dest_slice[..copy_len].copy_from_slice(&data[data_offset..data_offset + copy_len]);
        }
        if length > copy_len {
            dest_slice[copy_len..].fill(0);
        }
        Ok(())
    }
}

/// Rounds up `x` to the closest multiple of 32. If `x % 32 == 0` then `x` is returned.
#[inline]
fn next_multiple_of_32(x: usize) -> Option<usize> {
    let r = x.bitand(31).not().wrapping_add(1).bitand(31);
    x.checked_add(r)
}

#[cfg(test)]
mod tests {
    use super::next_multiple_of_32;

    #[test]
    fn test_next_multiple_of_32() {
        // next_multiple_of_32 returns x when it is a multiple of 32
        for i in 0..32 {
            let x = i * 32;
            assert_eq!(Some(x), next_multiple_of_32(x));
        }

        // next_multiple_of_32 rounds up to the nearest multiple of 32 when `x % 32 != 0`
        for x in 0..1024 {
            if x % 32 == 0 {
                continue;
            }
            let next_multiple = x + 32 - (x % 32);
            assert_eq!(Some(next_multiple), next_multiple_of_32(x));
        }

        // next_multiple_of_32 returns None when the next multiple of 32 is too big
        let last_multiple_of_32 = usize::MAX & !31;
        for i in 0..63 {
            let x = usize::MAX - i;
            if x > last_multiple_of_32 {
                assert_eq!(None, next_multiple_of_32(x));
            } else {
                assert_eq!(Some(last_multiple_of_32), next_multiple_of_32(x));
            }
        }
    }
}
