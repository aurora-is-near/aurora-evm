use super::prelude::*;
use super::Opcode;

/// Mapping of valid jump destination from code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Valids(Vec<bool>);

impl Valids {
    /// Create a new valid mapping from given code bytes.
    #[must_use]
    pub fn new(code: &[u8]) -> Self {
        let mut valids: Vec<bool> = Vec::with_capacity(code.len());
        valids.resize(code.len(), false);

        let mut i = 0;
        while i < code.len() {
            let opcode = Opcode(code[i]);
            if opcode == Opcode::JUMPDEST {
                valids[i] = true;
                i += 1;
            } else if let Some(v) = opcode.is_push() {
                i += usize::from(v) + 1;
            } else {
                i += 1;
            }
        }

        Self(valids)
    }

    /// Get the length of the valid mapping. This is the same as the
    /// code bytes.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the valids list is empty
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns `true` if the position is a valid jump destination. If
    /// not, returns `false`.
    #[must_use]
    pub fn is_valid(&self, position: usize) -> bool {
        if position >= self.0.len() {
            return false;
        }

        if !self.0[position] {
            return false;
        }

        true
    }
}
