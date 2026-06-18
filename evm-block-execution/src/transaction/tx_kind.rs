use primitive_types::H160;

/// The `to` field of a transaction. Either a target address, or empty for a
/// contract creation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum TxKind {
    /// A transaction that creates a contract.
    #[default]
    Create,
    /// A transaction that calls a contract or transfer.
    Call(H160),
}

impl From<Option<H160>> for TxKind {
    /// Creates a `TxKind::Call` with the `Some` address, `None` otherwise.
    #[inline]
    fn from(value: Option<H160>) -> Self {
        value.map_or(Self::Create, Self::Call)
    }
}

impl From<H160> for TxKind {
    /// Creates a `TxKind::Call` with the given address.
    #[inline]
    fn from(value: H160) -> Self {
        Self::Call(value)
    }
}

impl From<TxKind> for Option<H160> {
    /// Returns the address of the contract that will be called or will receive the transfer.
    #[inline]
    fn from(value: TxKind) -> Self {
        value.to().copied()
    }
}

impl TxKind {
    /// Returns the address of the contract that will be called or will receive the transfer.
    #[must_use]
    pub const fn to(&self) -> Option<&H160> {
        match self {
            Self::Create => None,
            Self::Call(to) => Some(to),
        }
    }

    /// Consumes the type and returns the address of the contract that will be called or will
    /// receive the transfer.
    #[must_use]
    pub const fn into_to(self) -> Option<H160> {
        match self {
            Self::Create => None,
            Self::Call(to) => Some(to),
        }
    }

    /// Returns true if the transaction is a contract creation.
    #[must_use]
    #[inline]
    pub const fn is_create(&self) -> bool {
        matches!(self, Self::Create)
    }

    /// Returns true if the transaction is a contract call.
    #[must_use]
    #[inline]
    pub const fn is_call(&self) -> bool {
        matches!(self, Self::Call(_))
    }
}

impl serde::Serialize for TxKind {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to().serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for TxKind {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Option::<H160>::deserialize(deserializer)?.into())
    }
}
