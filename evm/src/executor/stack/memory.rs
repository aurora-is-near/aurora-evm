use crate::backend::{code_hash_of, Apply, Backend, Basic, Log, KECCAK_EMPTY};
use crate::core::utils::{U256_ONE, U256_ZERO, U64_MAX};
use crate::executor::stack::executor::{
    Accessed, Authorization, StackState, StackSubstateMetadata,
};
use crate::prelude::*;
use crate::{ExitError, Transfer};
use core::cell::OnceCell;
use core::mem;
use primitive_types::{H160, H256, U256};

/// What the journal has recorded about an account's code.
///
/// A value is written only by `set_code`, or by assigning [`MemoryStackAccount::code`],
/// and describes the journal alone: this type never reads the backend and never caches
/// code read from it. The three variants are distinct states:
///
/// - [`NotSet`](Self::NotSet): the code was not set, so the backend code stays in effect;
/// - [`Empty`](Self::Empty): the code was set to empty bytes, so the account has no code
///   even if the backend still holds a contract;
/// - [`Bytecode`](Self::Bytecode): the code was set to these non-empty bytes.
///
/// The accessors [`as_bytes`](Self::as_bytes), [`hash`](Self::hash) and
/// [`into_bytes`](Self::into_bytes) return `None` for `NotSet` and `Some` for the other
/// two. On `None`, [`MemoryStackState`] asks the backend when the code is read and leaves
/// the backend code as is when the journal is applied.
///
/// A child frame starts with the value visible in its parent. Committing the child keeps
/// the value it set; reverting or discarding the child restores the parent's value.
/// Frames holding the same `Bytecode` share one buffer and one lazily computed hash, so a
/// hash first requested in a child that later reverts stays cached for the parent.
#[derive(Clone, Debug, Default)]
pub enum JournalCode {
    /// The code has not been set in the frames. The accessors return
    /// `None`: reads use the backend code, and applying the journal leaves that code as is.
    #[default]
    NotSet,
    /// The code was set to empty bytes. The accessors return empty code ([`KECCAK_EMPTY`]
    /// as its hash): the account has no code even if the backend holds a contract, and
    /// applying the journal clears the backend code.
    Empty,
    /// The code was set to these bytes, which are never empty. The accessors return them,
    /// and applying the journal writes them. Frames holding this version share the bytes
    /// and their lazily computed hash.
    Bytecode(Rc<CodeWithLazyHash>),
}

/// Immutable non-empty bytecode and its lazily computed Keccak-256 hash.
///
/// Frames sharing this version reuse the same bytes and cached hash.
#[derive(Debug)]
pub struct CodeWithLazyHash {
    code: Vec<u8>,
    hash: OnceCell<H256>,
}

impl CodeWithLazyHash {
    /// Borrows the bytecode without copying or hashing it.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        self.code.as_slice()
    }

    /// Returns the cached hash, computing it on first use.
    #[must_use]
    pub fn hash(&self) -> H256 {
        *self.hash.get_or_init(|| code_hash_of(&self.code))
    }
}

/// Records `code` as set, exactly as `set_code` does.
///
/// An empty vector records an explicit clear ([`JournalCode::Empty`]): the journal
/// neither retains its buffer nor allocates a hash cell. A non-empty vector becomes
/// a new [`JournalCode::Bytecode`] version without copying or hashing its bytes.
/// The result is never [`JournalCode::NotSet`]: use
/// `JournalCode::default()` to keep the backend code.
impl From<Vec<u8>> for JournalCode {
    fn from(code: Vec<u8>) -> Self {
        if code.is_empty() {
            return Self::Empty;
        }

        Self::Bytecode(Rc::new(CodeWithLazyHash {
            code,
            hash: OnceCell::new(),
        }))
    }
}

impl JournalCode {
    /// Borrows the recorded code without copying, hashing or reading the backend.
    ///
    /// Returns `None` for [`NotSet`](Self::NotSet), `Some(&[])` for [`Empty`](Self::Empty)
    /// and the bytes for [`Bytecode`](Self::Bytecode).
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::NotSet => None,
            Self::Empty => Some(&[]),
            Self::Bytecode(code) => Some(code.as_bytes()),
        }
    }

    /// Returns the Keccak-256 hash of the recorded code without reading the backend.
    ///
    /// Returns `None` for [`NotSet`](Self::NotSet) and [`KECCAK_EMPTY`] for
    /// [`Empty`](Self::Empty), both without hashing. For [`Bytecode`](Self::Bytecode) the
    /// hash is computed on the first call and then shared by every frame holding this
    /// version.
    #[must_use]
    pub fn hash(&self) -> Option<H256> {
        match self {
            Self::NotSet => None,
            Self::Empty => Some(KECCAK_EMPTY),
            Self::Bytecode(code) => Some(code.hash()),
        }
    }

    /// Whether the recorded code is non-empty; `None` when the code is not set.
    #[must_use]
    pub const fn has_code(&self) -> Option<bool> {
        match self {
            Self::NotSet => None,
            Self::Empty => Some(false),
            Self::Bytecode(_) => Some(true),
        }
    }

    /// Converts the record into the `code` field of [`Apply::Modify`].
    ///
    /// Returns `None` for [`NotSet`](Self::NotSet), which leaves the backend code as is,
    /// `Some` of an empty vector for [`Empty`](Self::Empty), which clears it, and the
    /// bytes for [`Bytecode`](Self::Bytecode). The buffer is moved out when this is the
    /// last handle to the version and copied when another handle still shares it.
    #[must_use]
    pub fn into_bytes(self) -> Option<Vec<u8>> {
        match self {
            Self::NotSet => None,
            Self::Empty => Some(Vec::new()),
            Self::Bytecode(code) => Some(match Rc::try_unwrap(code) {
                Ok(owned) => owned.code,
                Err(shared) => shared.code.clone(),
            }),
        }
    }
}

#[derive(Clone, Debug)]
pub struct MemoryStackAccount {
    pub basic: Basic,
    /// What was recorded for this account's code, as seen by the frame owning this entry.
    ///
    /// It is the journal's own record, not a cache: with [`JournalCode::NotSet`] the
    /// backend code is in effect and has been neither read nor copied here. Assigning a
    /// value has the effect of `set_code`: `bytes.into()` installs the bytes or, when
    /// they are empty, clears the code; [`JournalCode::NotSet`] drops the record so that
    /// the backend code is in effect again.
    pub code: JournalCode,
    pub reset: bool,
}

#[derive(Clone, Debug)]
pub struct MemoryStackSubstate<'config> {
    metadata: StackSubstateMetadata<'config>,
    parent: Option<Box<Self>>,
    logs: Vec<Log>,
    accounts: BTreeMap<H160, MemoryStackAccount>,
    storages: BTreeMap<(H160, H256), H256>,
    tstorages: BTreeMap<(H160, H256), U256>,
    deletes: BTreeSet<H160>,
    creates: BTreeSet<H160>,
}

impl<'config> MemoryStackSubstate<'config> {
    #[must_use]
    pub const fn new(metadata: StackSubstateMetadata<'config>) -> Self {
        Self {
            metadata,
            parent: None::<Box<_>>,
            logs: Vec::new(),
            accounts: BTreeMap::new(),
            storages: BTreeMap::new(),
            tstorages: BTreeMap::new(),
            deletes: BTreeSet::new(),
            creates: BTreeSet::new(),
        }
    }

    #[must_use]
    pub const fn logs(&self) -> &[Log] {
        self.logs.as_slice()
    }

    pub const fn logs_mut(&mut self) -> &mut Vec<Log> {
        &mut self.logs
    }

    #[must_use]
    pub const fn metadata(&self) -> &StackSubstateMetadata<'config> {
        &self.metadata
    }

    pub const fn metadata_mut(&mut self) -> &mut StackSubstateMetadata<'config> {
        &mut self.metadata
    }

    /// Deconstruct the memory stack substate, return state to be applied. Panic if the
    /// substate is not in the top-level substate.
    ///
    /// ## Panics
    /// It panics if parent presents
    #[must_use]
    pub fn deconstruct<B: Backend>(
        mut self,
        backend: &B,
    ) -> (
        impl IntoIterator<Item = Apply<impl IntoIterator<Item = (H256, H256)>>>,
        impl IntoIterator<Item = Log>,
    ) {
        assert!(self.parent.is_none());

        let mut applies = Vec::<Apply<BTreeMap<H256, H256>>>::new();

        let mut addresses = BTreeSet::new();

        for address in self.accounts.keys() {
            addresses.insert(*address);
        }

        for (address, _) in self.storages.keys() {
            addresses.insert(*address);
        }

        for address in addresses {
            if self.deletes.contains(&address) {
                continue;
            }

            let mut storage = BTreeMap::new();
            for ((oa, ok), ov) in &self.storages {
                if *oa == address {
                    storage.insert(*ok, *ov);
                }
            }

            let apply = {
                let account = if self.is_created(address) {
                    let account = self
                        .accounts
                        .get_mut(&address)
                        .expect("New account was just inserted");
                    // Reset storage for CREATE call as initially it's always should be empty.
                    // NOTE: related to `ethereum-tests`: `stSStoreTest/InitCollisionParis.json`
                    account.reset = true;
                    account
                } else {
                    self.account_mut(address, backend)
                };

                Apply::Modify {
                    address,
                    basic: account.basic.clone(),
                    code: mem::take(&mut account.code).into_bytes(),
                    storage,
                    reset_storage: account.reset,
                }
            };

            applies.push(apply);
        }

        for address in self.deletes {
            applies.push(Apply::Delete { address });
        }

        (applies, self.logs)
    }

    pub fn enter(&mut self, gas_limit: u64, is_static: bool) {
        let mut entering = Self {
            metadata: self.metadata.spit_child(gas_limit, is_static),
            parent: None,
            logs: Vec::new(),
            accounts: BTreeMap::new(),
            storages: BTreeMap::new(),
            tstorages: BTreeMap::new(),
            deletes: BTreeSet::new(),
            creates: BTreeSet::new(),
        };
        mem::swap(&mut entering, self);

        self.parent = Some(Box::new(entering));
    }

    /// Commits the current frame's gas, accesses, logs and state changes to its parent.
    ///
    /// # Errors
    /// Return `ExitError` that is thrown by gasometer gas calculation errors.
    ///
    /// # Panics
    /// Cannot commit on root `substate` i.e. it forces to panic.
    pub fn exit_commit(&mut self) -> Result<(), ExitError> {
        let mut exited = *self.parent.take().expect("Cannot commit on root substate");
        mem::swap(&mut exited, self);

        self.metadata.swallow_commit(exited.metadata)?;
        self.logs.append(&mut exited.logs);

        self.commit_accounts(exited.accounts);
        self.storages.append(&mut exited.storages);
        self.tstorages.append(&mut exited.tstorages);
        self.deletes.append(&mut exited.deletes);
        self.creates.append(&mut exited.creates);
        Ok(())
    }

    /// Merges a successful child's account entries into this parent frame.
    ///
    /// Only a reset issued by the child clears the parent's pending slot writes. Otherwise
    /// the child's account data replaces the parent's but preserves any earlier reset.
    /// The caller merges the child's slot writes afterwards, so writes after a reset survive.
    fn commit_accounts(&mut self, child_accounts: BTreeMap<H160, MemoryStackAccount>) {
        // Collect child resets before merging flags: a parent reset must not clear slots twice.
        let resets: BTreeSet<_> = child_accounts
            .iter()
            .filter_map(|(address, account)| account.reset.then_some(*address))
            .collect();

        // Only parent writes are in this map; exit_commit appends the child's writes afterwards.
        if !resets.is_empty() {
            self.storages
                .retain(|(address, _), _| !resets.contains(address));
        }

        // With no parent account entries to reconcile, move the whole child map.
        if self.accounts.is_empty() {
            self.accounts = child_accounts;
            return;
        }

        for (address, mut child) in child_accounts {
            match self.accounts.entry(address) {
                Entry::Occupied(mut parent) => {
                    // The child's account data wins, but a touch must not undo a parent's reset.
                    child.reset |= parent.get().reset;
                    parent.insert(child);
                }
                Entry::Vacant(entry) => {
                    // No parent entry for this address: keep the child's reset flag as-is.
                    entry.insert(child);
                }
            }
        }
    }

    /// Exit revert. Represents revert execution of the `substate`.
    ///
    /// # Errors
    /// Return `ExitError`
    ///
    /// # Panics
    /// Cannot discard on root substate
    pub fn exit_revert(&mut self) -> Result<(), ExitError> {
        let mut exited = *self.parent.take().expect("Cannot discard on root substate");
        mem::swap(&mut exited, self);
        self.metadata.swallow_revert(&exited.metadata)?;
        Ok(())
    }

    /// Exit discard. Represents discard execution of the `substate`.
    ///
    /// # Errors
    /// Return `ExitError`. At the moment it's not throwing any real error.
    ///
    /// # Panics
    /// Cannot discard on root substate
    pub fn exit_discard(&mut self) -> Result<(), ExitError> {
        let mut exited = *self.parent.take().expect("Cannot discard on root substate");
        mem::swap(&mut exited, self);
        self.metadata.swallow_discard(&exited.metadata);
        Ok(())
    }

    /// Get known account from the current state. If it's `None` just take a look
    /// recursively in the parent state.
    #[must_use]
    pub fn known_account(&self, address: H160) -> Option<&MemoryStackAccount> {
        self.accounts.get(&address).or_else(|| {
            self.parent
                .as_ref()
                .and_then(|parent| parent.known_account(address))
        })
    }

    /// Get known basic data from the current accounts state.
    /// If it's `None` just take a look.
    #[must_use]
    pub fn known_basic(&self, address: H160) -> Option<Basic> {
        self.known_account(address).map(|acc| acc.basic.clone())
    }

    /// Returns an owned copy of journaled code, or `None` if the backend supplies it.
    #[must_use]
    pub fn known_code(&self, address: H160) -> Option<Vec<u8>> {
        self.journaled_code(address).as_bytes().map(<[u8]>::to_vec)
    }

    fn journaled_code(&self, address: H160) -> &JournalCode {
        self.known_account(address)
            .map_or(&JournalCode::NotSet, |account| &account.code)
    }

    /// Get known empty status of the account from the current accounts state.
    /// If it's `None` just take a look.
    #[must_use]
    pub fn known_storage(&self, address: H160, key: H256) -> Option<H256> {
        if let Some(value) = self.storages.get(&(address, key)) {
            return Some(*value);
        }

        if let Some(account) = self.accounts.get(&address) {
            if account.reset {
                return Some(H256::default());
            }
        }

        if let Some(parent) = self.parent.as_ref() {
            return parent.known_storage(address, key);
        }

        None
    }

    /// A journaled reset makes every slot originally zero; otherwise consult the backend.
    #[must_use]
    pub fn known_original_storage(&self, address: H160) -> Option<H256> {
        if let Some(account) = self.accounts.get(&address) {
            if account.reset {
                return Some(H256::default());
            }
        }

        if let Some(parent) = self.parent.as_ref() {
            return parent.known_original_storage(address);
        }

        None
    }

    #[must_use]
    pub fn is_cold(&self, address: H160) -> bool {
        self.recursive_is_cold(&|a| a.accessed_addresses.contains(&address))
    }

    #[must_use]
    pub fn is_storage_cold(&self, address: H160, key: H256) -> bool {
        self.recursive_is_cold(&|a: &Accessed| a.accessed_storage.contains(&(address, key)))
    }

    fn recursive_is_cold<F: Fn(&Accessed) -> bool>(&self, f: &F) -> bool {
        !self.metadata.accessed().as_ref().is_some_and(f)
            && self.parent.as_ref().is_none_or(|p| p.recursive_is_cold(f))
    }

    /// Check if the account was deleted in the current substate or any of its parents.
    #[must_use]
    pub fn deleted(&self, address: H160) -> bool {
        self.deletes.contains(&address)
            || self
                .parent
                .as_ref()
                .is_some_and(|parent| parent.deleted(address))
    }

    fn account_mut<B: Backend>(&mut self, address: H160, backend: &B) -> &mut MemoryStackAccount {
        self.accounts.entry(address).or_insert_with(|| {
            Self::load_account_for_frame(self.parent.as_deref(), address, backend)
        })
    }

    /// Inherits the nearest journal entry or loads only the backend's basic fields.
    #[inline]
    fn load_account_for_frame<B: Backend>(
        parent: Option<&Self>,
        address: H160,
        backend: &B,
    ) -> MemoryStackAccount {
        if let Some(account) = parent.and_then(|frame| frame.known_account(address)) {
            return MemoryStackAccount {
                basic: account.basic.clone(),
                code: account.code.clone(),
                // The parent still owns any storage reset it recorded.
                reset: false,
            };
        }

        MemoryStackAccount {
            basic: backend.basic(address),
            code: JournalCode::NotSet,
            reset: false,
        }
    }

    /// # Errors
    /// Return `ExitError`
    pub fn inc_nonce<B: Backend>(&mut self, address: H160, backend: &B) -> Result<(), ExitError> {
        let nonce = &mut self.account_mut(address, backend).basic.nonce;
        if *nonce >= U64_MAX {
            return Err(ExitError::MaxNonce);
        }
        *nonce += U256_ONE;
        Ok(())
    }

    pub fn set_storage(&mut self, address: H160, key: H256, value: H256) {
        #[cfg(feature = "print-debug")]
        println!("    [SSTORE {address:?}] {key:?}:{value:?}");
        self.storages.insert((address, key), value);
    }

    pub fn reset_storage<B: Backend>(&mut self, address: H160, backend: &B) {
        let mut removing = Vec::new();

        for (oa, ok) in self.storages.keys() {
            if *oa == address {
                removing.push(*ok);
            }
        }

        for ok in removing {
            self.storages.remove(&(address, ok));
        }
        self.account_mut(address, backend).reset = true;
    }

    pub fn log(&mut self, address: H160, topics: Vec<H256>, data: Vec<u8>) {
        self.logs.push(Log {
            address,
            topics,
            data,
        });
    }

    pub fn set_deleted(&mut self, address: H160) {
        self.deletes.insert(address);
    }

    pub fn set_created(&mut self, address: H160) {
        self.creates.insert(address);
    }

    /// Check if the account was created in the current substate or any of its parents.
    #[must_use]
    pub fn is_created(&self, address: H160) -> bool {
        self.creates.contains(&address)
            || self
                .parent
                .as_ref()
                .is_some_and(|parent| parent.is_created(address))
    }

    /// Records `code` for the account in the current frame, replacing any earlier record.
    ///
    /// Empty bytes record [`JournalCode::Empty`] without allocating; non-empty bytes
    /// record a new [`JournalCode::Bytecode`] version whose hash is not computed yet.
    pub fn set_code<B: Backend>(&mut self, address: H160, code: Vec<u8>, backend: &B) {
        self.account_mut(address, backend).code = code.into();
    }

    /// # Errors
    /// Return `ExitError`
    pub fn transfer<B: Backend>(
        &mut self,
        transfer: &Transfer,
        backend: &B,
    ) -> Result<(), ExitError> {
        {
            let source = self.account_mut(transfer.source, backend);
            if source.basic.balance < transfer.value {
                return Err(ExitError::OutOfFund);
            }
            source.basic.balance -= transfer.value;
        }

        {
            let target = self.account_mut(transfer.target, backend);
            target.basic.balance = target.basic.balance.saturating_add(transfer.value);
        }

        Ok(())
    }

    /// Only needed for jsontests.
    /// # Errors
    /// Return `ExitError`
    pub fn withdraw<B: Backend>(
        &mut self,
        address: H160,
        value: U256,
        backend: &B,
    ) -> Result<(), ExitError> {
        let source = self.account_mut(address, backend);
        if source.basic.balance < value {
            return Err(ExitError::OutOfFund);
        }
        source.basic.balance -= value;

        Ok(())
    }

    // Only needed for jsontests.
    pub fn deposit<B: Backend>(&mut self, address: H160, value: U256, backend: &B) {
        let target = self.account_mut(address, backend);
        target.basic.balance = target.basic.balance.saturating_add(value);
    }

    pub fn reset_balance<B: Backend>(&mut self, address: H160, backend: &B) {
        self.account_mut(address, backend).basic.balance = U256_ZERO;
    }

    pub fn touch<B: Backend>(&mut self, address: H160, backend: &B) {
        self.account_mut(address, backend);
    }

    #[must_use]
    pub fn get_tstorage(&self, address: H160, key: H256) -> U256 {
        self.known_tstorage(address, key).unwrap_or_default()
    }

    #[must_use]
    pub fn known_tstorage(&self, address: H160, key: H256) -> Option<U256> {
        if let Some(value) = self.tstorages.get(&(address, key)) {
            return Some(*value);
        }
        if let Some(parent) = self.parent.as_ref() {
            return parent.known_tstorage(address, key);
        }
        None
    }

    pub fn set_tstorage(&mut self, address: H160, key: H256, value: U256) {
        self.tstorages.insert((address, key), value);
    }

    /// Get authority target from the current state. If it's `None` just take a look
    /// recursively in the parent state.
    fn get_authority_target_recursive(&self, authority: H160) -> Option<H160> {
        if let Some(target) = self
            .metadata
            .accessed()
            .as_ref()
            .and_then(|accessed| accessed.get_authority_target(authority))
        {
            return Some(target);
        }
        self.parent
            .as_ref()
            .and_then(|p| p.get_authority_target_recursive(authority))
    }
}

#[derive(Clone, Debug)]
pub struct MemoryStackState<'backend, 'config, B> {
    backend: &'backend B,
    substate: MemoryStackSubstate<'config>,
}

impl<B: Backend> Backend for MemoryStackState<'_, '_, B> {
    fn gas_price(&self) -> U256 {
        self.backend.gas_price()
    }
    fn origin(&self) -> H160 {
        self.backend.origin()
    }
    fn block_hash(&self, number: U256) -> H256 {
        self.backend.block_hash(number)
    }
    fn block_number(&self) -> U256 {
        self.backend.block_number()
    }
    fn block_coinbase(&self) -> H160 {
        self.backend.block_coinbase()
    }
    fn block_timestamp(&self) -> U256 {
        self.backend.block_timestamp()
    }
    fn block_difficulty(&self) -> U256 {
        self.backend.block_difficulty()
    }
    fn block_randomness(&self) -> Option<H256> {
        self.backend.block_randomness()
    }
    fn block_gas_limit(&self) -> U256 {
        self.backend.block_gas_limit()
    }
    fn block_base_fee_per_gas(&self) -> U256 {
        self.backend.block_base_fee_per_gas()
    }

    fn chain_id(&self) -> U256 {
        self.backend.chain_id()
    }

    fn exists(&self, address: H160) -> bool {
        self.substate.known_account(address).is_some() || self.backend.exists(address)
    }

    fn basic(&self, address: H160) -> Basic {
        self.substate
            .known_basic(address)
            .unwrap_or_else(|| self.backend.basic(address))
    }

    /// Returns the account's bytecode as seen by the current frame.
    ///
    /// [`MemoryStackSubstate::known_code`] checks the nearest journal entry, starting
    /// in this frame and walking up to its parents. An explicit empty override returns
    /// an empty vector; a non-empty override returns an owned copy of its bytes.
    /// Neither case reads the backend.
    ///
    /// This is the stack state's only direct call to the underlying [`Backend::code`]:
    /// it is made when there is no entry or its code is [`JournalCode::NotSet`].
    /// The returned bytes are not cached in the journal. Hash and presence queries
    /// use separate backend methods, which may themselves load code.
    fn code(&self, address: H160) -> Vec<u8> {
        self.substate
            .known_code(address)
            .unwrap_or_else(|| self.backend.code(address))
    }

    fn code_hash(&self, address: H160) -> H256 {
        self.substate
            .journaled_code(address)
            .hash()
            .unwrap_or_else(|| self.backend.code_hash(address))
    }

    fn has_code(&self, address: H160) -> bool {
        self.substate
            .journaled_code(address)
            .has_code()
            .unwrap_or_else(|| self.backend.has_code(address))
    }

    fn storage(&self, address: H160, key: H256) -> H256 {
        self.substate
            .known_storage(address, key)
            .unwrap_or_else(|| self.backend.storage(address, key))
    }

    fn is_empty_storage(&self, address: H160) -> bool {
        self.backend.is_empty_storage(address)
    }

    fn original_storage(&self, address: H160, key: H256) -> H256 {
        self.substate
            .known_original_storage(address)
            .unwrap_or_else(|| self.backend.original_storage(address, key))
    }
    fn blob_gas_price(&self) -> Option<u128> {
        self.backend.blob_gas_price()
    }
    fn get_blob_hash(&self, index: usize) -> Option<U256> {
        self.backend.get_blob_hash(index)
    }
}

impl<'config, B: Backend> StackState<'config> for MemoryStackState<'_, 'config, B> {
    fn metadata(&self) -> &StackSubstateMetadata<'config> {
        self.substate.metadata()
    }

    fn metadata_mut(&mut self) -> &mut StackSubstateMetadata<'config> {
        self.substate.metadata_mut()
    }

    fn enter(&mut self, gas_limit: u64, is_static: bool) {
        self.substate.enter(gas_limit, is_static);
    }

    fn exit_commit(&mut self) -> Result<(), ExitError> {
        self.substate.exit_commit()
    }

    fn exit_revert(&mut self) -> Result<(), ExitError> {
        self.substate.exit_revert()
    }

    fn exit_discard(&mut self) -> Result<(), ExitError> {
        self.substate.exit_discard()
    }

    /// EIP-161 emptiness. The code is tested for presence only, through `Backend::has_code`,
    /// which is therefore a contract on the backend:
    /// - a backend that always holds the code may keep the default, derived from `code`;
    /// - a witness backend, where an account may carry its `code_hash` without the code
    ///   bytes, must override `has_code` to return `code_hash != KECCAK_EMPTY` instead of
    ///   fetching the code, which the witness is not required to contain for this check.
    fn is_empty(&self, address: H160) -> bool {
        if let Some(account) = self.substate.known_account(address) {
            if !account.basic.balance.is_zero() || !account.basic.nonce.is_zero() {
                return false;
            }

            return !account
                .code
                .has_code()
                .unwrap_or_else(|| self.backend.has_code(address));
        }

        let basic = self.backend.basic(address);
        basic.balance.is_zero() && basic.nonce.is_zero() && !self.backend.has_code(address)
    }

    fn deleted(&self, address: H160) -> bool {
        self.substate.deleted(address)
    }

    fn is_cold(&self, address: H160) -> bool {
        self.substate.is_cold(address)
    }

    fn is_storage_cold(&self, address: H160, key: H256) -> bool {
        self.substate.is_storage_cold(address, key)
    }

    fn inc_nonce(&mut self, address: H160) -> Result<(), ExitError> {
        self.substate.inc_nonce(address, self.backend)
    }

    fn set_storage(&mut self, address: H160, key: H256, value: H256) {
        self.substate.set_storage(address, key, value);
    }

    fn reset_storage(&mut self, address: H160) {
        self.substate.reset_storage(address, self.backend);
    }

    fn log(&mut self, address: H160, topics: Vec<H256>, data: Vec<u8>) {
        self.substate.log(address, topics, data);
    }

    fn set_deleted(&mut self, address: H160) {
        self.substate.set_deleted(address);
    }

    fn set_created(&mut self, address: H160) {
        self.substate.set_created(address);
    }

    fn is_created(&self, address: H160) -> bool {
        self.substate.is_created(address)
    }

    fn set_code(&mut self, address: H160, code: Vec<u8>) {
        self.substate.set_code(address, code, self.backend);
    }

    fn transfer(&mut self, transfer: Transfer) -> Result<(), ExitError> {
        self.substate.transfer(&transfer, self.backend)
    }

    fn reset_balance(&mut self, address: H160) {
        self.substate.reset_balance(address, self.backend);
    }

    fn touch(&mut self, address: H160) {
        self.substate.touch(address, self.backend);
    }

    fn tload(&mut self, address: H160, index: H256) -> Result<U256, ExitError> {
        Ok(self.substate.get_tstorage(address, index))
    }

    fn tstore(&mut self, address: H160, index: H256, value: U256) -> Result<(), ExitError> {
        self.substate.set_tstorage(address, index, value);
        Ok(())
    }

    /// EIP-7702 - check is authority cold.
    fn is_authority_cold(&mut self, address: H160) -> Option<bool> {
        self.get_authority_target(address)
            .map(|target| self.is_cold(target))
    }

    /// Get authority target (EIP-7702) - delegated address.
    /// First we're trying to get authority target from the cache recursively with parent state,
    /// if it's not found we get code for the authority address and check if it's delegation
    /// designator. If it's true, we add result to cache and return delegated target address.
    fn get_authority_target(&mut self, authority: H160) -> Option<H160> {
        // Read from cache
        if let Some(target_address) = self.substate.get_authority_target_recursive(authority) {
            Some(target_address)
        } else {
            // If not found in the cache
            // Get code for delegated address
            let authority_code = self.code(authority);
            if let Some(target) = Authorization::get_delegated_address(&authority_code) {
                // Add to cache
                self.metadata_mut().add_authority(authority, target);
                return Some(target);
            }
            None
        }
    }
}

impl<'backend, 'config, B: Backend> MemoryStackState<'backend, 'config, B> {
    pub const fn new(metadata: StackSubstateMetadata<'config>, backend: &'backend B) -> Self {
        Self {
            backend,
            substate: MemoryStackSubstate::new(metadata),
        }
    }

    /// Returns this frame's journal entry. Editing account data preserves the code's
    /// cached hash; replacing its `code` selects a different code version.
    pub fn account_mut(&mut self, address: H160) -> &mut MemoryStackAccount {
        self.substate.account_mut(address, self.backend)
    }

    #[must_use]
    pub fn deconstruct(
        self,
    ) -> (
        impl IntoIterator<Item = Apply<impl IntoIterator<Item = (H256, H256)>>>,
        impl IntoIterator<Item = Log>,
    ) {
        self.substate.deconstruct(self.backend)
    }

    /// # Errors
    /// Return `ExitError`
    pub fn withdraw(&mut self, address: H160, value: U256) -> Result<(), ExitError> {
        self.substate.withdraw(address, value, self.backend)
    }

    pub fn deposit(&mut self, address: H160, value: U256) {
        self.substate.deposit(address, value, self.backend);
    }
}

#[cfg(test)]
mod tests {
    use super::{CodeWithLazyHash, JournalCode, MemoryStackState};
    use crate::backend::{
        code_hash_of, Backend, MemoryAccount, MemoryBackend, MemoryVicinity, KECCAK_EMPTY,
    };
    use crate::executor::stack::executor::StackSubstateMetadata;
    use crate::executor::stack::StackState;
    use crate::prelude::*;
    use crate::Config;
    use primitive_types::{H160, H256, U256};

    // Inspect this frame's own entry: a fallback to the parent would mask a missing child entry.
    fn shared_code<'a>(
        state: &'a MemoryStackState<'_, '_, impl Backend>,
        address: H160,
    ) -> &'a Rc<CodeWithLazyHash> {
        let account = &state.substate.accounts[&address];
        let JournalCode::Bytecode(code) = &account.code else {
            panic!("expected shared code in the current frame");
        };
        code
    }

    fn memory_vicinity() -> MemoryVicinity {
        MemoryVicinity {
            gas_price: U256::from(1),
            effective_gas_price: U256::zero(),
            origin: H160::zero(),
            block_hashes: Vec::new(),
            block_number: U256::zero(),
            block_coinbase: H160::zero(),
            block_timestamp: U256::zero(),
            block_difficulty: U256::zero(),
            block_randomness: None,
            blob_gas_price: None,
            block_gas_limit: U256::from(30_000_000),
            block_base_fee_per_gas: U256::from(1),
            chain_id: U256::from(1),
            blob_hashes: vec![],
        }
    }

    #[test]
    fn first_hash_read_in_a_reverting_child_populates_the_parent_cache() {
        let address = H160::from_low_u64_be(1);
        let code = vec![0x60; 24_576];
        let expected = code_hash_of(&code);
        let config = Config::osaka();
        let vicinity = memory_vicinity();
        let backend = MemoryBackend::new(&vicinity, BTreeMap::new());
        let mut state = MemoryStackState::new(StackSubstateMetadata::new(0, &config), &backend);
        state.set_code(address, code);
        let parent = Rc::clone(shared_code(&state, address));

        assert_eq!(parent.hash.get(), None);

        state.enter(0, false);
        state.touch(address);
        state.enter(0, false);
        state.touch(address);

        assert!(Rc::ptr_eq(&parent, shared_code(&state, address)));
        assert_eq!(parent.hash.get(), None);
        assert_eq!(state.code_hash(address), expected);

        state.exit_revert().unwrap();
        state.exit_discard().unwrap();

        // Inspect the parent before another code_hash call can fill a missing cache.
        let restored = shared_code(&state, address);

        assert!(Rc::ptr_eq(restored, &parent));
        assert_eq!(restored.hash.get(), Some(&expected));
    }

    #[test]
    fn a_child_commit_reuses_unhashed_code_and_its_original_buffer() {
        let address = H160::from_low_u64_be(1);
        let code = vec![0x5b; 24_576];
        let buffer = code.as_ptr();
        let config = Config::osaka();
        let vicinity = memory_vicinity();
        let backend = MemoryBackend::new(&vicinity, BTreeMap::new());
        let mut state = MemoryStackState::new(StackSubstateMetadata::new(0, &config), &backend);
        state.set_code(address, code);
        let parent = Rc::clone(shared_code(&state, address));
        state.enter(0, false);
        state.touch(address);
        let child = shared_code(&state, address);

        assert!(state.has_code(address));
        assert!(Rc::ptr_eq(&parent, child));
        assert_eq!(child.code.as_ptr(), buffer);
        assert_eq!(child.hash.get(), None);

        state.exit_commit().unwrap();
        let committed = shared_code(&state, address);

        assert!(Rc::ptr_eq(committed, &parent));
        assert_eq!(committed.hash.get(), None);
    }

    #[test]
    fn replacing_code_creates_an_independent_lazy_version() {
        let address = H160::from_low_u64_be(1);
        let config = Config::osaka();
        let vicinity = memory_vicinity();
        let backend = MemoryBackend::new(&vicinity, BTreeMap::new());

        for commit in [false, true] {
            let mut state = MemoryStackState::new(StackSubstateMetadata::new(0, &config), &backend);
            state.set_code(address, vec![0x00]);
            let original = Rc::clone(shared_code(&state, address));
            state.enter(0, false);
            state.set_code(address, vec![0x5b]);
            let replacement = Rc::clone(shared_code(&state, address));

            assert!(!Rc::ptr_eq(&original, &replacement));
            assert_eq!(replacement.hash.get(), None);

            let expected = code_hash_of(&[0x5b]);

            assert_eq!(state.code_hash(address), expected);
            assert_eq!(replacement.hash.get(), Some(&expected));
            assert_eq!(original.hash.get(), None);

            if commit {
                state.exit_commit().unwrap();

                assert!(Rc::ptr_eq(shared_code(&state, address), &replacement));
                assert_eq!(state.code_hash(address), expected);
            } else {
                state.exit_revert().unwrap();

                assert!(Rc::ptr_eq(shared_code(&state, address), &original));
                assert_eq!(state.code_hash(address), code_hash_of(&[0x00]));
            }
        }
    }

    #[test]
    fn replacing_hashed_code_does_not_reuse_the_previous_hash() {
        let address = H160::from_low_u64_be(1);
        let config = Config::osaka();
        let vicinity = memory_vicinity();
        let backend = MemoryBackend::new(&vicinity, BTreeMap::new());
        let mut state = MemoryStackState::new(StackSubstateMetadata::new(0, &config), &backend);
        state.set_code(address, vec![0x00]);

        assert_eq!(state.code_hash(address), code_hash_of(&[0x00]));

        state.set_code(address, vec![0x5b]);

        assert!(shared_code(&state, address).hash.get().is_none());
        assert_eq!(state.code_hash(address), code_hash_of(&[0x5b]));
    }

    #[test]
    fn public_account_edits_replace_only_the_child_code() {
        let address = H160::from_low_u64_be(1);
        let config = Config::osaka();
        let vicinity = memory_vicinity();
        let backend = MemoryBackend::new(&vicinity, BTreeMap::new());
        let mut state = MemoryStackState::new(StackSubstateMetadata::new(0, &config), &backend);
        state.set_code(address, vec![0x00]);
        let expected = state.code_hash(address);
        let original = Rc::clone(shared_code(&state, address));

        state.enter(0, false);
        state.account_mut(address).basic.balance = U256::one();

        assert!(Rc::ptr_eq(shared_code(&state, address), &original));

        state.account_mut(address).code = vec![0x5b].into();
        let replacement = shared_code(&state, address);
        let replacement_hash = code_hash_of(&[0x5b]);

        assert_eq!(replacement.hash.get(), None);
        assert_eq!(state.code_hash(address), replacement_hash);
        assert_eq!(replacement.hash.get(), Some(&replacement_hash));

        state.exit_revert().unwrap();

        assert!(Rc::ptr_eq(shared_code(&state, address), &original));
        assert_eq!(original.hash.get(), Some(&expected));
        assert_eq!(state.code_hash(address), expected);
    }

    #[test]
    fn touching_an_account_keeps_backend_code_until_replaced() {
        let address = H160::from_low_u64_be(1);
        let config = Config::osaka();
        let vicinity = memory_vicinity();
        let account = MemoryAccount {
            code: vec![0x5b],
            ..MemoryAccount::default()
        };
        let backend = MemoryBackend::new(&vicinity, BTreeMap::from([(address, account)]));
        let mut state = MemoryStackState::new(StackSubstateMetadata::new(0, &config), &backend);

        state.touch(address);

        assert!(matches!(
            state.substate.journaled_code(address),
            JournalCode::NotSet
        ));
        assert_eq!(state.code_hash(address), code_hash_of(&[0x5b]));
        assert!(matches!(
            state.substate.journaled_code(address),
            JournalCode::NotSet
        ));

        state.set_code(address, vec![0x00]);
        state.set_code(address, Vec::new());

        assert_eq!(state.code_hash(address), KECCAK_EMPTY);
        assert!(matches!(
            state.substate.journaled_code(address),
            JournalCode::Empty
        ));
    }

    #[test]
    fn reverting_calls_cache_the_created_code_hash() {
        use crate::executor::stack::StackExecutor;

        // ADDRESS; EXTCODEHASH; MSTORE(0); REVERT(0, 32), padded to maximum code size.
        let mut runtime = vec![0x30, 0x3f, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xfd];
        runtime.resize(24_576, 0);
        let expected = code_hash_of(&runtime);
        let mut init = vec![
            0x61, 0x60, 0, 0x61, 0, 15, 0x60, 0, 0x39, 0x61, 0x60, 0, 0x60, 0, 0xf3,
        ];
        init.extend_from_slice(&runtime);
        let len = u16::try_from(init.len()).unwrap().to_be_bytes();
        // Copy appended initcode, CREATE, and save the returned address at memory[32].
        let mut code = vec![
            0x61, len[0], len[1], 0x61, 0, 0, 0x60, 0, 0x39, 0x61, len[0], len[1], 0x60, 0, 0x60,
            0, 0xf0, 0x60, 32, 0x52,
        ];

        for i in 0..100_u16 {
            let offset = (64 + i * 64).to_be_bytes();
            code.extend_from_slice(&[
                0x60, 32, 0x61, offset[0], offset[1], 0x60, 0, 0x60, 0, 0x60, 0, 0x60, 32, 0x51,
                0x61, 0x07, 0xd0, 0xf1,
            ]);
            let status_offset = (96 + i * 64).to_be_bytes();
            code.extend_from_slice(&[0x61, status_offset[0], status_offset[1], 0x52]);
        }

        // Return the created address followed by the 100 (hash, status) pairs.
        code.extend_from_slice(&[0x61, 0x19, 0x20, 0x60, 32, 0xf3]);
        let init_offset = u16::try_from(code.len()).unwrap().to_be_bytes();
        code[4..6].copy_from_slice(&init_offset);
        code.extend_from_slice(&init);
        let caller = H160::from_low_u64_be(0xca);
        let creator = H160::from_low_u64_be(0xcc);
        let vicinity = memory_vicinity();
        let backend = MemoryBackend::new(
            &vicinity,
            BTreeMap::from([
                (caller, MemoryAccount::default()),
                (
                    creator,
                    MemoryAccount {
                        code,
                        ..MemoryAccount::default()
                    },
                ),
            ]),
        );

        let config = Config::osaka();
        let limit = 10_000_000;
        let state = MemoryStackState::new(StackSubstateMetadata::new(limit, &config), &backend);
        let mut executor = StackExecutor::new_with_precompiles(state, &config, &());
        let (reason, output) = executor.transact_call(
            caller,
            creator,
            U256::zero(),
            Vec::new(),
            limit,
            Vec::new(),
            Vec::new(),
        );

        assert!(reason.is_succeed(), "{reason:?}");
        assert_eq!(output.len(), 6_432);

        let (address, results) = output.split_at(32);
        let created = H160::from(H256::from_slice(address));

        // Only the reverted calls read the hash. Inspect their shared cell without filling it.
        assert_eq!(
            shared_code(executor.state(), created).hash.get(),
            Some(&expected)
        );

        for result in results.as_chunks::<64>().0 {
            assert_eq!(&result[..32], expected.as_bytes());
            assert_eq!(&result[32..], &[0; 32]); // Every CALL reverted with its hash as data.
        }
    }

    #[test]
    fn created_code_hash_remains_cached_after_repeated_extcodehash() {
        use crate::executor::stack::StackExecutor;

        let caller = H160::from_low_u64_be(0xca);
        let creator = H160::from_low_u64_be(0xcc);
        // Store the six-byte initcode RETURN(0, 24576), then CREATE from that slice.
        let mut code = vec![
            0x65, 0x61, 0x60, 0, 0x60, 0, 0xf3, 0x60, 0, 0x52, 0x60, 6, 0x60, 26, 0x60, 0, 0xf0,
        ];

        for _ in 0..100 {
            code.extend_from_slice(&[0x80, 0x3f, 0x50]); // DUP1; EXTCODEHASH; POP.
        }

        code.extend_from_slice(&[0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3]);
        let expected = code_hash_of(&vec![0; 24_576]);
        let config = Config::osaka();
        let vicinity = memory_vicinity();
        let backend = MemoryBackend::new(
            &vicinity,
            BTreeMap::from([
                (caller, MemoryAccount::default()),
                (
                    creator,
                    MemoryAccount {
                        code,
                        ..MemoryAccount::default()
                    },
                ),
            ]),
        );

        let limit = 10_000_000;
        let state = MemoryStackState::new(StackSubstateMetadata::new(limit, &config), &backend);
        let mut executor = StackExecutor::new_with_precompiles(state, &config, &());
        let (reason, output) = executor.transact_call(
            caller,
            creator,
            U256::zero(),
            Vec::new(),
            limit,
            Vec::new(),
            Vec::new(),
        );

        assert!(reason.is_succeed(), "{reason:?}");

        let created = H160::from(H256::from_slice(&output));

        assert!(!created.is_zero());
        assert_eq!(executor.state().code(created).len(), 24_576);
        assert_eq!(
            shared_code(executor.state(), created).hash.get(),
            Some(&expected)
        );
        assert_eq!(executor.state().code_hash(created), expected);
    }

    #[test]
    fn reverting_delegated_call_caches_the_last_designator_hash() {
        use crate::executor::stack::{Authorization, StackExecutor};

        let caller = H160::from_low_u64_be(0xca);
        let authority = H160::from_low_u64_be(0xaa);
        let old_target = H160::from_low_u64_be(0xd1);
        let target = H160::from_low_u64_be(0xd2);
        // Delegated code runs at the authority address and reverts with EXTCODEHASH(ADDRESS).
        let delegate = MemoryAccount {
            code: vec![0x30, 0x3f, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xfd],
            ..MemoryAccount::default()
        };
        let config = Config::prague();
        let vicinity = memory_vicinity();
        let backend = MemoryBackend::new(&vicinity, BTreeMap::from([(target, delegate)]));
        let limit = 200_000;
        let state = MemoryStackState::new(StackSubstateMetadata::new(limit, &config), &backend);
        let mut executor = StackExecutor::new_with_precompiles(state, &config, &());
        let mut designator = vec![0xef, 0x01, 0x00];
        designator.extend_from_slice(target.as_bytes());
        let expected = code_hash_of(&designator);
        let (reason, output) = executor.transact_call(
            caller,
            authority,
            U256::zero(),
            Vec::new(),
            limit,
            Vec::new(),
            vec![
                Authorization::new(authority, old_target, 0, true),
                Authorization::new(authority, target, 1, true),
            ],
        );

        assert!(reason.is_revert(), "{reason:?}");
        assert_eq!(output, expected.as_bytes());
        assert_eq!(executor.state().basic(authority).nonce, U256::from(2));
        assert_eq!(executor.state().code(authority), designator);
        assert_eq!(
            shared_code(executor.state(), authority).hash.get(),
            Some(&expected)
        );
    }

    #[test]
    fn clearing_a_delegation_leaves_no_hash_cell() {
        use crate::executor::stack::{Authorization, StackExecutor};

        let caller = H160::from_low_u64_be(0xca);
        let authority = H160::from_low_u64_be(0xaa);
        let target = H160::from_low_u64_be(0xd1);
        let config = Config::prague();
        let vicinity = memory_vicinity();
        let backend = MemoryBackend::new(&vicinity, BTreeMap::new());
        let limit = 200_000;
        let state = MemoryStackState::new(StackSubstateMetadata::new(limit, &config), &backend);
        let mut executor = StackExecutor::new_with_precompiles(state, &config, &());
        let (reason, _) = executor.transact_call(
            caller,
            authority,
            U256::zero(),
            Vec::new(),
            limit,
            Vec::new(),
            vec![
                Authorization::new(authority, target, 0, true),
                Authorization::new(authority, H160::zero(), 1, true),
            ],
        );

        assert!(reason.is_succeed(), "{reason:?}");
        assert_eq!(executor.state().basic(authority).nonce, U256::from(2));
        assert_eq!(executor.state().code(authority), Vec::<u8>::new());
        assert_eq!(executor.state().code_hash(authority), KECCAK_EMPTY);
        assert!(matches!(
            executor.state().substate.journaled_code(authority),
            JournalCode::Empty
        ));
    }

    #[test]
    fn test_is_empty_catch_backend_only() {
        let mut state = BTreeMap::new();

        let addr1 = H160::from_low_u64_be(1);
        state.insert(
            addr1,
            MemoryAccount {
                balance: U256::one(),
                nonce: U256::zero(),
                storage: BTreeMap::new(),
                code: Vec::new(),
            },
        );

        let addr2 = H160::from_low_u64_be(2);
        state.insert(
            addr2,
            MemoryAccount {
                balance: U256::zero(),
                nonce: U256::one(),
                storage: BTreeMap::new(),
                code: Vec::new(),
            },
        );

        let addr3 = H160::from_low_u64_be(3);
        state.insert(
            addr3,
            MemoryAccount {
                balance: U256::zero(),
                nonce: U256::zero(),
                storage: BTreeMap::new(),
                code: vec![0x42],
            },
        );

        let addr4 = H160::from_low_u64_be(4);
        state.insert(
            addr4,
            MemoryAccount {
                balance: U256::zero(),
                nonce: U256::zero(),
                storage: BTreeMap::new(),
                code: Vec::new(),
            },
        );

        let vicinity = memory_vicinity();
        let backend = MemoryBackend::new(&vicinity, state);
        let config = Config::osaka();
        let metadata = StackSubstateMetadata::new(0, &config);

        let stack_state = MemoryStackState::new(metadata, &backend);

        assert!(!stack_state.is_empty(addr1));
        assert!(!stack_state.is_empty(addr2));
        assert!(!stack_state.is_empty(addr3));
        assert!(stack_state.is_empty(addr4));
    }

    #[test]
    fn test_is_empty_with_cached_account() {
        let mut state = BTreeMap::new();

        let addr1 = H160::from_low_u64_be(1);
        state.insert(
            addr1,
            MemoryAccount {
                balance: U256::zero(),
                nonce: U256::zero(),
                storage: BTreeMap::new(),
                code: Vec::new(),
            },
        );

        let addr2 = H160::from_low_u64_be(2);
        state.insert(
            addr2,
            MemoryAccount {
                balance: U256::zero(),
                nonce: U256::zero(),
                storage: BTreeMap::new(),
                code: vec![0x42],
            },
        );

        let vicinity = memory_vicinity();
        let backend = MemoryBackend::new(&vicinity, state);
        let config = Config::osaka();
        let metadata = StackSubstateMetadata::new(0, &config);

        let mut stack_state = MemoryStackState::new(metadata, &backend);

        assert!(stack_state.is_empty(addr1));
        assert!(!stack_state.is_empty(addr2));

        // Accounts cached
        stack_state.deposit(addr1, U256::one());
        stack_state.deposit(addr2, U256::one());

        // Cached account
        assert!(!stack_state.is_empty(addr1));

        // Updating balances leaves the backend code unchanged.
        let acc1 = stack_state.substate.known_account(addr1).unwrap();
        let acc2 = stack_state.substate.known_account(addr2).unwrap();

        assert_eq!(acc1.basic.balance, U256::one());
        assert!(matches!(acc1.code, JournalCode::NotSet));
        assert_eq!(acc2.basic.balance, U256::one());
        // NOTE: code is not cached
        assert!(matches!(acc2.code, JournalCode::NotSet));

        stack_state.reset_balance(addr1);

        // Get from cache and code from backend.
        assert!(stack_state.is_empty(addr1));
        assert_eq!(stack_state.code(addr1), Vec::<u8>::new());

        stack_state.reset_balance(addr2);
        let acc2 = stack_state.substate.known_account(addr2).unwrap();

        assert_eq!(acc2.basic.balance, U256::zero());
        // NOTE: code is not cached
        assert!(matches!(acc2.code, JournalCode::NotSet));
        // Get code from backend, but in backend code is not empty, so account is not empty.
        assert!(!stack_state.is_empty(addr2));
        // Get code from backend, but in backend code is not empty
        assert_eq!(stack_state.code(addr2), vec![0x42]);
    }

    fn account(balance: u64, nonce: u64, code: Vec<u8>) -> MemoryAccount {
        MemoryAccount {
            balance: U256::from(balance),
            nonce: U256::from(nonce),
            storage: BTreeMap::new(),
            code,
        }
    }

    /// `has_code` is `code_hash != KECCAK_EMPTY`, and `code_hash` is the hash of `code`.
    fn assert_code_invariants<B: Backend>(
        stack_state: &MemoryStackState<'_, '_, B>,
        address: H160,
    ) {
        let code_hash = stack_state.code_hash(address);

        assert_eq!(code_hash, code_hash_of(&stack_state.code(address)));
        assert_eq!(stack_state.has_code(address), code_hash != KECCAK_EMPTY);
    }

    #[test]
    fn test_code_hash_and_has_code_from_backend() {
        let eoa = H160::from_low_u64_be(1);
        let contract = H160::from_low_u64_be(2);
        let absent = H160::from_low_u64_be(3);
        let code = vec![0x42];
        let state = BTreeMap::from([
            (eoa, account(1, 0, Vec::new())),
            (contract, account(0, 1, code.clone())),
        ]);

        let vicinity = memory_vicinity();
        let backend = MemoryBackend::new(&vicinity, state);
        let config = Config::osaka();
        let metadata = StackSubstateMetadata::new(0, &config);

        let mut stack_state = MemoryStackState::new(metadata, &backend);

        assert_eq!(stack_state.code_hash(eoa), KECCAK_EMPTY);
        assert!(!stack_state.has_code(eoa));
        assert_eq!(stack_state.code_hash(absent), KECCAK_EMPTY);
        assert!(!stack_state.has_code(absent));
        assert_eq!(stack_state.code_hash(contract), code_hash_of(&code));
        assert!(stack_state.has_code(contract));

        // A cached account without code changes still answers from the backend.
        stack_state.deposit(contract, U256::one());
        stack_state.deposit(absent, U256::one());

        assert!(stack_state
            .substate
            .accounts
            .values()
            .all(|account| matches!(account.code, JournalCode::NotSet)));
        assert_eq!(stack_state.code_hash(contract), code_hash_of(&code));
        assert!(stack_state.has_code(contract));
        assert_eq!(stack_state.code_hash(absent), KECCAK_EMPTY);
        assert!(!stack_state.has_code(absent));

        for address in [eoa, contract, absent] {
            assert_code_invariants(&stack_state, address);
        }
    }

    #[test]
    fn test_code_hash_and_has_code_from_substate() {
        let eoa = H160::from_low_u64_be(1);
        let contract = H160::from_low_u64_be(2);
        let new_code = vec![0x60, 0x01, 0x00];
        let state = BTreeMap::from([
            (eoa, account(0, 0, Vec::new())),
            (contract, account(0, 0, vec![0x42])),
        ]);

        let vicinity = memory_vicinity();
        let backend = MemoryBackend::new(&vicinity, state);
        let config = Config::osaka();
        let metadata = StackSubstateMetadata::new(0, &config);

        let mut stack_state = MemoryStackState::new(metadata, &backend);

        assert!(stack_state.is_empty(eoa));
        assert!(!stack_state.is_empty(contract));

        // Code set in the substate shadows the backend.
        stack_state.set_code(eoa, new_code.clone());

        assert_eq!(stack_state.code_hash(eoa), code_hash_of(&new_code));
        assert!(stack_state.has_code(eoa));
        assert!(!stack_state.is_empty(eoa));
        assert_code_invariants(&stack_state, eoa);

        // Cleared code makes the account empty although the backend still holds code.
        stack_state.set_code(contract, Vec::new());

        assert_eq!(stack_state.code_hash(contract), KECCAK_EMPTY);
        assert!(!stack_state.has_code(contract));
        assert!(stack_state.is_empty(contract));
        assert!(backend.has_code(contract));
        assert_code_invariants(&stack_state, contract);
    }

    #[test]
    fn test_code_hash_and_has_code_across_substates() {
        let address = H160::from_low_u64_be(1);
        let code = vec![0x42];
        let new_code = vec![0x60, 0x01, 0x00];
        let state = BTreeMap::from([(address, account(0, 0, code.clone()))]);

        let vicinity = memory_vicinity();
        let backend = MemoryBackend::new(&vicinity, state);
        let config = Config::osaka();
        let metadata = StackSubstateMetadata::new(0, &config);

        let mut stack_state = MemoryStackState::new(metadata, &backend);

        // A reverted substate drops its code change.
        stack_state.enter(0, false);
        stack_state.set_code(address, new_code.clone());

        assert_eq!(stack_state.code_hash(address), code_hash_of(&new_code));

        stack_state.exit_revert().unwrap();

        assert_eq!(stack_state.code_hash(address), code_hash_of(&code));
        assert!(stack_state.has_code(address));

        // A committed substate keeps it, visible from the parent.
        stack_state.enter(0, false);
        stack_state.set_code(address, Vec::new());
        stack_state.enter(0, false);

        assert_eq!(stack_state.code_hash(address), KECCAK_EMPTY);
        assert!(!stack_state.has_code(address));

        stack_state.exit_commit().unwrap();
        stack_state.exit_commit().unwrap();

        assert_eq!(stack_state.code_hash(address), KECCAK_EMPTY);
        assert!(!stack_state.has_code(address));
        assert!(stack_state.is_empty(address));
        assert_code_invariants(&stack_state, address);
    }
}
