use crate::config::TestConfig;
use crate::types::Spec;
use crate::types::{InvalidTxReason, PostState};
use aurora_evm::{ExitError, ExitReason};

/// Assert vicinity validation to ensure that the test expected validation error
#[allow(clippy::cognitive_complexity, clippy::too_many_lines)]
pub fn assert_vicinity_validation(
    reason: &InvalidTxReason,
    states: &[PostState],
    spec: &Spec,
    test_config: &TestConfig,
) {
    let name = &test_config.name;
    let file_name = &test_config.file_name;
    match *spec {
        Spec::Istanbul | Spec::Berlin => match reason {
            InvalidTxReason::GasPriceEip1559 => {
                for (i, state) in states.iter().enumerate() {
                    let expected = state.expect_exception.as_deref().unwrap_or_else(|| {
                        panic!(
                            "expected error message for test: [{spec:?}] {name}:{i}\n{file_name:?}"
                        )
                    });

                    let is_checked =
                        expected == "TR_TypeNotSupported" || expected == "TR_TypeNotSupportedBlob";
                    assert!(
                        is_checked,
                        "unexpected error message {expected:?} for: [{spec:?}] {name}:{i}\n{file_name:?}",
                    );
                }
            }
            _ => panic!("Unexpected validation reason: {reason:?} [{name}]\n{file_name:?}"),
        },
        Spec::London => match reason {
            InvalidTxReason::PriorityFeeTooLarge => {
                for (i, state) in states.iter().enumerate() {
                    let expected = state.expect_exception.as_deref().unwrap_or_else(|| {
                        panic!("expected error message for test: {reason:?} [{spec:?}] {name}:{i}\n{file_name:?}")
                    });
                    let is_checked = expected == "tipTooHigh" || expected == "TR_TipGtFeeCap";
                    assert!(
                        is_checked,
                        "unexpected error message {expected:?} for: {reason:?} [{spec:?}] {name}:{i}\n{file_name:?}",
                    );
                }
            }
            InvalidTxReason::GasPriceLessThanBlockBaseFee => {
                for (i, state) in states.iter().enumerate() {
                    let expected = state.expect_exception.as_deref().unwrap_or_else(|| {
                        panic!("expected error message for test: {reason:?} [{spec:?}] {name}:{i}\n{file_name:?}")
                    });
                    let is_checked =
                        expected == "lowFeeCap" || expected == "TR_FeeCapLessThanBlocks";
                    assert!(
                        is_checked,
                        "unexpected error message {expected:?} for: {reason:?} [{spec:?}] {name}:{i}\n{file_name:?}",
                    );
                }
            }
            _ => {
                panic!("Unexpected validation reason: {reason:?} [{spec:?}] {name}\n{file_name:?}")
            }
        },
        Spec::Merge => match reason {
            InvalidTxReason::PriorityFeeTooLarge => {
                for (i, state) in states.iter().enumerate() {
                    let expected = state.expect_exception.as_deref().unwrap_or_else(|| {
                        panic!("expected error message for test: {reason:?} [{spec:?}] {name}:{i}\n{file_name:?}")
                    });
                    let is_checked = expected == "TR_TipGtFeeCap";
                    assert!(
                        is_checked,
                        "unexpected error message {expected:?} for: {reason:?} [{spec:?}] {name}:{i}\n{file_name:?}",
                    );
                }
            }
            InvalidTxReason::GasPriceLessThanBlockBaseFee => {
                for (i, state) in states.iter().enumerate() {
                    let expected = state.expect_exception.as_deref().unwrap_or_else(|| {
                        panic!("expected error message for test: {reason:?} [{spec:?}] {name}:{i}\n{file_name:?}")
                    });
                    let is_checked = expected == "TR_FeeCapLessThanBlocks";
                    assert!(
                        is_checked,
                        "unexpected error message {expected:?} for: {reason:?} [{spec:?}] {name}:{i}\n{file_name:?}",
                    );
                }
            }
            _ => {
                panic!("Unexpected validation reason: {reason:?} [{spec:?}] {name}\n{file_name:?}")
            }
        },
        Spec::Shanghai => match reason {
            InvalidTxReason::PriorityFeeTooLarge => {
                for (i, state) in states.iter().enumerate() {
                    let expected = state.expect_exception.as_deref().unwrap_or_else(|| {
                        panic!("expected error message for test: {reason:?} [{spec:?}] {name}:{i}\n{file_name:?}")
                    });
                    let is_checked = expected == "TR_TipGtFeeCap";
                    assert!(
                        is_checked,
                        "unexpected error message {expected:?} for: {reason:?} [{spec:?}] {name}:{i}\n{file_name:?}",
                    );
                }
            }
            InvalidTxReason::GasPriceLessThanBlockBaseFee => {
                for (i, state) in states.iter().enumerate() {
                    let expected = state.expect_exception.as_deref().unwrap_or_else(|| {
                        panic!("expected error message for test: {reason:?} [{spec:?}] {name}:{i}\n{file_name:?}")
                    });

                    let is_checked = expected == "TR_FeeCapLessThanBlocks";
                    assert!(
                        is_checked,
                        "unexpected error message {expected:?} for: {reason:?} [{spec:?}] {name}:{i}\n{file_name:?}",
                    );
                }
            }
            _ => {
                panic!("Unexpected validation reason: {reason:?} [{spec:?}] {name}\n{file_name:?}")
            }
        },
        Spec::Cancun => match reason {
            InvalidTxReason::PriorityFeeTooLarge => {
                for (i, state) in states.iter().enumerate() {
                    let expected = state.expect_exception.as_deref().unwrap_or_else(|| {
                        panic!("expected error message for test: {reason:?} [{spec:?}] {name}:{i}\n{file_name:?}")
                    });

                    let is_checked = expected == "TR_TipGtFeeCap"
                        || expected == "TransactionException.PRIORITY_GREATER_THAN_MAX_FEE_PER_GAS";
                    assert!(
                        is_checked,
                        "unexpected error message {expected:?} for: {reason:?} [{spec:?}] {name}:{i}\n{file_name:?}",
                    );
                }
            }
            InvalidTxReason::GasPriceLessThanBlockBaseFee => {
                for (i, state) in states.iter().enumerate() {
                    let expected = state.expect_exception.as_deref().unwrap_or_else(|| {
                        panic!("expected error message for test: {reason:?} [{spec:?}] {name}:{i}\n{file_name:?}")
                    });

                    let is_checked = expected == "TR_FeeCapLessThanBlocks"
                        || expected == "TransactionException.INSUFFICIENT_MAX_FEE_PER_GAS";
                    assert!(
                        is_checked,
                        "unexpected error message {expected:?} for: {reason:?} [{spec:?}] {name}:{i}\n{file_name:?}",
                    );
                }
            }
            _ => {
                panic!("Unexpected validation reason: {reason:?} [{spec:?}] {name}\n{file_name:?}")
            }
        },
        Spec::Prague => match reason {
            InvalidTxReason::PriorityFeeTooLarge => {
                for (i, state) in states.iter().enumerate() {
                    let expected = state.expect_exception.as_deref().unwrap_or_else(|| {
                        panic!("expected error message for test: {reason:?} [{spec:?}] {name}:{i}\n{file_name:?}")
                    });

                    let is_checked =
                        expected == "TransactionException.PRIORITY_GREATER_THAN_MAX_FEE_PER_GAS";
                    assert!(
                        is_checked,
                        "unexpected error message {expected:?} for: {reason:?} [{spec:?}] {name}:{i}\n{file_name:?}",
                    );
                }
            }

            InvalidTxReason::GasPriceLessThanBlockBaseFee => {
                for (i, state) in states.iter().enumerate() {
                    let expected = state.expect_exception.as_deref().unwrap_or_else(|| {
                        panic!("expected error message for test: {reason:?} [{spec:?}] {name}:{i}\n{file_name:?}")
                    });
                    let is_checked = expected == "TR_FeeCapLessThanBlocks"
                        || expected == "TransactionException.INSUFFICIENT_MAX_FEE_PER_GAS";
                    assert!(
                        is_checked,
                        "unexpected error message {expected:?} for: {reason:?} [{spec:?}] {name}:{i}\n{file_name:?}",
                    );
                }
            }
            _ => {
                panic!("Unexpected validation reason: {reason:?} [{spec:?}] {name}\n{file_name:?}")
            }
        },
        _ => panic!("Unexpected validation reason: {reason:?} [{spec:?}] {name}\n{file_name:?}"),
    }
}

/// Check Exit Reason of EVM execution
#[allow(clippy::too_many_lines)]
pub fn check_validate_exit_reason(
    reason: &InvalidTxReason,
    expect_exception: Option<&String>,
    name: &str,
    spec: &Spec,
) -> bool {
    expect_exception.map_or_else(
        || {
            panic!("unexpected validation error reason: {reason:?} {name}");
        },
        |exception| {
            match reason {
                InvalidTxReason::OutOfFund => {
                    let check_result = exception
                        == "TransactionException.INSUFFICIENT_ACCOUNT_FUNDS"
                        || exception == "TR_NoFunds"
                        || exception == "TR_NoFundsX"
                        || exception == "TransactionException.INSUFFICIENT_MAX_FEE_PER_BLOB_GAS"
                        || exception == "TransactionException.INSUFFICIENT_ACCOUNT_FUNDS|TransactionException.GASLIMIT_PRICE_PRODUCT_OVERFLOW";
                    assert!(
                        check_result,
                        "unexpected exception {exception:?} for OutOfFund for test: [{spec:?}] {name}"
                    );
                }
                InvalidTxReason::GasLimitReached => {
                    let check_result = exception == "TR_GasLimitReached"
                        || exception == "TransactionException.GAS_ALLOWANCE_EXCEEDED";
                    assert!(
                        check_result,
                        "unexpected exception {exception:?} for GasLimitReached for test: [{spec:?}] {name}"
                    );
                }
                InvalidTxReason::IntrinsicGas => {
                    let check_result = exception == "TR_NoFundsOrGas"
                        || exception == "TR_IntrinsicGas"
                        || exception == "TransactionException.INTRINSIC_GAS_TOO_LOW"
                        || exception == "IntrinsicGas"
                        || exception == "TransactionException.INSUFFICIENT_ACCOUNT_FUNDS|TransactionException.INTRINSIC_GAS_TOO_LOW";
                    assert!(
                        check_result,
                        "unexpected exception {exception:?} for IntrinsicGas for test: [{spec:?}] {name}"
                    );
                }
                InvalidTxReason::BlobVersionNotSupported => {
                    let check_result = exception
                        == "TransactionException.TYPE_3_TX_INVALID_BLOB_VERSIONED_HASH"
                        || exception == "TR_BLOBVERSION_INVALID";
                    assert!(
                        check_result,
                        "unexpected exception {exception:?} for BlobVersionNotSupported for test: [{spec:?}] {name}"
                    );
                }
                InvalidTxReason::BlobCreateTransaction => {
                    let check_result = exception == "TR_BLOBCREATE"
                        || exception == "TransactionException.TYPE_3_TX_CONTRACT_CREATION";
                    assert!(
                        check_result,
                        "unexpected exception {exception:?} for BlobCreateTransaction for test: [{spec:?}] {name}"
                    );
                }
                InvalidTxReason::BlobGasPriceGreaterThanMax => {
                    let check_result =
                        exception == "TransactionException.INSUFFICIENT_MAX_FEE_PER_BLOB_GAS";
                    assert!(
                        check_result,
                        "unexpected exception {exception:?} for BlobGasPriceGreaterThanMax for test: [{spec:?}] {name}"
                    );
                }
                InvalidTxReason::TooManyBlobs => {
                    let check_result = exception == "TR_BLOBLIST_OVERSIZE"
                        || exception == "TransactionException.TYPE_3_TX_BLOB_COUNT_EXCEEDED"
                        || exception == "TransactionException.TYPE_3_TX_MAX_BLOB_GAS_ALLOWANCE_EXCEEDED|TransactionException.TYPE_3_TX_BLOB_COUNT_EXCEEDED";
                    assert!(
                        check_result,
                        "unexpected exception {exception:?} for TooManyBlobs for test: [{spec:?}] {name}"
                    );
                }
                InvalidTxReason::EmptyBlobs => {
                    let check_result = exception == "TransactionException.TYPE_3_TX_ZERO_BLOBS"
                        || exception == "TR_EMPTYBLOB";
                    assert!(
                        check_result,
                        "unexpected exception {exception:?} for EmptyBlobs for test: [{spec:?}] {name}"
                    );
                }
                InvalidTxReason::MaxFeePerBlobGasNotSupported => {
                    let check_result =
                        exception == "TransactionException.TYPE_3_TX_PRE_FORK|TransactionException.TYPE_3_TX_ZERO_BLOBS";
                    assert!(
                        check_result,
                        "unexpected exception {exception:?} for MaxFeePerBlobGasNotSupported for test: [{spec:?}] {name}"
                    );
                }
                InvalidTxReason::BlobVersionedHashesNotSupported => {
                    let check_result = exception == "TransactionException.TYPE_3_TX_PRE_FORK"
                        || exception == "TR_TypeNotSupportedBlob";
                    assert!(
                        check_result,
                        "unexpected exception {exception:?} for BlobVersionedHashesNotSupported for test: [{spec:?}] {name}"
                    );
                }
                InvalidTxReason::InvalidAuthorizationChain => {
                    let check_result = exception == "TransactionException.TYPE_4_INVALID_AUTHORIZATION_FORMAT";
                    assert!(
                        check_result,
                        "unexpected exception {exception:?} for InvalidAuthorizationChain for test: [{spec:?}] {name}"
                    );
                }
                InvalidTxReason::InvalidAuthorizationSignature => {
                    let check_result = exception == "TransactionException.TYPE_4_INVALID_AUTHORITY_SIGNATURE";
                    assert!(
                        check_result,
                        "unexpected exception {exception:?} for InvalidAuthorizationSignature for test: [{spec:?}] {name}"
                    );
                }
                InvalidTxReason::AuthorizationListNotExist => {
                    let check_result = exception == "TransactionException.TYPE_4_EMPTY_AUTHORIZATION_LIST" || exception == "TransactionException.TYPE_4_TX_CONTRACT_CREATION";
                    assert!(
                        check_result,
                        "unexpected exception {exception:?} for AuthorizationListNotExist for test: [{spec:?}] {name}"
                    );
                }
                InvalidTxReason::CreateTransaction => {
                    let check_result = exception == "TransactionException.TYPE_4_TX_CONTRACT_CREATION";
                    assert!(
                        check_result,
                        "unexpected exception {exception:?} for CreateTransaction for test: [{spec:?}] {name}"
                    );
                }
                InvalidTxReason::GasFloorMoreThanGasLimit => {
                    let check_result = exception == "TransactionException.INTRINSIC_GAS_TOO_LOW";
                    assert!(
                        check_result,
                        "unexpected exception {exception:?} for GasFloorMoreThanGasLimit for test: [{spec:?}] {name}"
                    );
                }
                _ => {
                    panic!(
                        "unexpected exception {exception:?} for reason {reason:?} for test: [{spec:?}] {name}"
                    );
                }
            }
            true
        },
    )
}

/// Validate EIP-3607 - empty create caller
pub fn assert_empty_create_caller(expect_exception: Option<&String>, name: &str) {
    let exception = expect_exception.expect("expected evm-json-test exception");
    let check_exception =
        exception == "SenderNotEOA" || exception == "TransactionException.SENDER_NOT_EOA";
    assert!(
        check_exception,
        "expected EmptyCaller exception for test: {name}: {expect_exception:?}"
    );
}

/// Check call expected exception
pub fn assert_call_exit_exception(expect_exception: Option<&String>, name: &str) {
    assert!(
        expect_exception.is_none(),
        "unexpected call exception: {expect_exception:?} for test: {name}"
    );
}

/// Check Exit Reason of EVM execution
pub fn check_create_exit_reason(
    reason: &ExitReason,
    expect_exception: Option<&String>,
    name: &str,
) -> bool {
    match reason {
        ExitReason::Error(err) => {
            if let Some(exception) = expect_exception {
                match err {
                    ExitError::CreateContractLimit => {
                        let check_result = exception == "TR_InitCodeLimitExceeded"
                            || exception == "TransactionException.INITCODE_SIZE_EXCEEDED";
                        assert!(
                            check_result,
                            "unexpected exception {exception:?} for CreateContractLimit error for test: {name}"
                        );
                        return true;
                    }
                    ExitError::MaxNonce => {
                        let check_result = exception == "TR_NonceHasMaxValue"
                            || exception == "TransactionException.NONCE_IS_MAX";
                        assert!(check_result,
                                "unexpected exception {exception:?} for MaxNonce error for test: {name}"
                        );
                        return true;
                    }
                    ExitError::OutOfGas => {
                        let check_result =
                            exception == "TransactionException.INTRINSIC_GAS_TOO_LOW";
                        assert!(check_result,
                                "unexpected exception {exception:?} for OutOfGas error for test: {name}"
                        );
                        return true;
                    }
                    _ => {
                        panic!(
                            "unexpected error: {err:?} for exception: {exception} for test: {name}"
                        )
                    }
                }
            } else {
                return false;
            }
        }
        ExitReason::Fatal(err) => {
            panic!("Unexpected error: {err:?}")
        }
        _ => {
            assert!(
                expect_exception.is_none(),
                "Unexpected json-test error: {expect_exception:?}"
            );
        }
    }
    false
}
