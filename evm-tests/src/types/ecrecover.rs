use aurora_evm::ExitError;
use primitive_types::{H160, H256};
use sha3::{Digest, Keccak256};
use std::borrow::Cow;

pub fn ecrecover(hash: H256, signature: &[u8]) -> Result<H160, ExitError> {
    let hash = libsecp256k1::Message::parse_slice(hash.as_bytes())
        .map_err(|e| ExitError::Other(Cow::from(e.to_string())))?;
    let v = signature[64];
    let signature = libsecp256k1::Signature::parse_standard_slice(&signature[0..64])
        .map_err(|e| ExitError::Other(Cow::from(e.to_string())))?;
    let bit = match v {
        0..=26 => v,
        _ => v - 27,
    };

    if let Ok(recovery_id) = libsecp256k1::RecoveryId::parse(bit) {
        if let Ok(public_key) = libsecp256k1::recover(&hash, &signature, &recovery_id) {
            // recover returns a 65-byte key, but addresses come from the raw 64-byte key
            let r = Keccak256::digest(&public_key.serialize()[1..]);
            return Ok(H160::from_slice(&r[12..]));
        }
    }

    Err(ExitError::Other(Cow::from("ECRecoverErr unknown error")))
}

#[cfg(test)]
mod tests {
    use super::ecrecover;
    use aurora_evm::ExitError;
    use hex_literal::hex;
    use primitive_types::{H160, H256};
    use std::borrow::Cow;

    #[test]
    fn test_ecrecover_success() {
        let hash = H256::from_slice(&hex!(
            "47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad"
        ));
        let signature = hex!("650acf9d3f5f0a2c799776a1254355d5f4061762a237396a99a0e0e3fc2bcd6729514a0dacb2e623ac4abd157cb18163ff942280db4d5caad66ddf941ba12e031b");
        let expected_address = H160::from_slice(&hex!("c08b5542d177ac6686946920409741463a15dddb"));

        let result = ecrecover(hash, &signature).expect("ecrecover should succeed");
        assert_eq!(result, expected_address);
    }

    #[test]
    fn test_ecrecover_invalid_signature() {
        let hash = H256::from_slice(&hex!(
            "47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad"
        ));
        let signature = hex!("00650acf9d3f5f0a2c799776a1254355d5f4061762a237396a99a0e0e3fc2bcd6729514a0dacb2e623ac4abd157cb18163ff942280db4d5caad66ddf941ba12e031c");

        let result = ecrecover(hash, &signature);
        assert_eq!(
            result,
            Err(ExitError::Other(Cow::from("ECRecoverErr unknown error")))
        );
    }

    #[test]
    fn test_ecrecover_invalid_recovery_id() {
        let hash = H256::from_slice(&hex!(
            "47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad"
        ));
        let signature = hex!("650acf9d3f5f0a2c799776a1254355d5f4061762a237396a99a0e0e3fc2bcd6729514a0dacb2e623ac4abd157cb18163ff942280db4d5caad66ddf941ba12e0327");

        let result = ecrecover(hash, &signature);
        assert_eq!(
            result,
            Err(ExitError::Other(Cow::from("ECRecoverErr unknown error")))
        );
    }
}
