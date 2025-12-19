//! EIP-7702 - Prague hard fork
#![allow(clippy::missing_errors_doc)]

use crate::types::ecrecover::ecrecover;
use aurora_evm::ExitError;
use primitive_types::{H160, H256, U256};
use rlp::RlpStream;
use sha3::{Digest, Keccak256};

pub const MAGIC: u8 = 0x5;
/// The order of the secp256k1 curve, divided by two. Signatures that should be checked according
/// to EIP-2 should have an S value less than or equal to this.
///
/// `57896044618658097711785492504343953926418782139537452191302581570759080747168`
pub const SECP256K1N_HALF: U256 = U256([
    0xDFE9_2F46_681B_20A0,
    0x5D57_6E73_57A4_501D,
    0xFFFF_FFFF_FFFF_FFFF,
    0x7FFF_FFFF_FFFF_FFFF,
]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorization {
    pub chain_id: U256,
    pub address: H160,
    pub nonce: u64,
}

impl Authorization {
    #[must_use]
    pub const fn new(chain_id: U256, address: H160, nonce: u64) -> Self {
        Self {
            chain_id,
            address,
            nonce,
        }
    }

    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(3);
        s.append(&self.chain_id);
        s.append(&self.address);
        s.append(&self.nonce);
    }

    #[must_use]
    pub fn signature_hash(&self) -> H256 {
        let mut rlp_stream = RlpStream::new();
        rlp_stream.append(&MAGIC);
        self.rlp_append(&mut rlp_stream);
        H256::from_slice(<[u8; 32]>::from(Keccak256::digest(rlp_stream.as_raw())).as_slice())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAuthorization {
    chain_id: U256,
    address: H160,
    nonce: u64,
    v: bool,
    r: U256,
    s: U256,
}

impl SignedAuthorization {
    #[must_use]
    pub const fn new(chain_id: U256, address: H160, nonce: u64, r: U256, s: U256, v: bool) -> Self {
        Self {
            chain_id,
            address,
            nonce,
            v,
            r,
            s,
        }
    }

    pub fn recover_address(&self) -> Result<H160, ExitError> {
        let auth = Authorization::new(self.chain_id, self.address, self.nonce).signature_hash();
        ecrecover(auth, &vrs_to_arr(self.v, self.r, self.s))
    }
}

/// v, r, s signature values to array
fn vrs_to_arr(v: bool, r: U256, s: U256) -> [u8; 65] {
    let mut result = [0u8; 65]; // (r, s, v), typed (uint256, uint256, uint8)
    result[..32].copy_from_slice(&r.to_big_endian());
    result[32..64].copy_from_slice(&s.to_big_endian());
    result[64] = u8::from(v);
    result
}
