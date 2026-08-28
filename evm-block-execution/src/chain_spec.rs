//! Trusted chain configuration and Cancun-or-later hardfork activation.
//!
//! [`ChainSpec::spec`] is an explicit upper bound: timestamps select a fork within it but cannot
//! advance beyond it. Pre-Cancun activation rules are omitted because Cancun is the zkEVM's minimum.

use crate::eips::eip1559::BaseFeeParams;
use crate::eips::eip7840::BlobParams;
use crate::eips::eip7892::BlobScheduleBlobParams;
use crate::spec::Spec;
use primitive_types::H160;
use std::collections::BTreeMap;

/// Activation timestamps for the Cancun-and-later hardforks supported by the zkEVM.
pub type HardForkActivationTime = BTreeMap<Spec, u64>;

/// Trusted chain parameters used to validate and execute a block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainSpec {
    /// EIP-155 chain id.
    pub chain_id: u64,
    /// The trusted hardfork boundary this block is executed under.
    pub spec: Spec,
    /// Activation timestamps for supported timestamp-activated hardforks.
    pub hard_forks_timestamps: HardForkActivationTime,
    /// Deposit contract address, when configured.
    pub deposit_contract_address: Option<H160>,
    /// EIP-1559 base-fee parameters.
    pub base_fee_params: BaseFeeParams,
    /// Blob-parameter schedule (EIP-7840 / EIP-7892 BPO forks).
    pub blob_schedule: BlobScheduleBlobParams,
}

impl ChainSpec {
    /// Returns the [`BlobParams`] active at `timestamp`, bounded by [`Self::spec`].
    ///
    /// Returns `None` when Cancun is inactive or its activation timestamp is unavailable. Osaka uses
    /// the latest active scheduled update, falling back to its fork defaults.
    #[must_use]
    pub fn blob_params_at_timestamp(&self, timestamp: u64) -> Option<BlobParams> {
        // BPO updates are reachable only from Osaka, so a late timestamp cannot advance a spec-pinned
        // Cancun or Prague configuration.
        if self.is_osaka_active_at_timestamp(timestamp) {
            self.blob_schedule
                .active_scheduled_params_at_timestamp(timestamp)
                .copied()
                .or(Some(self.blob_schedule.osaka))
        } else if self.is_prague_active_at_timestamp(timestamp) {
            Some(self.blob_schedule.prague)
        } else if self.is_cancun_active_at_timestamp(timestamp) {
            Some(self.blob_schedule.cancun)
        } else {
            None
        }
    }

    /// Whether Cancun is active within the configured boundary.
    #[must_use]
    fn is_cancun_active_at_timestamp(&self, timestamp: u64) -> bool {
        self.spec >= Spec::Cancun && self.active_at_timestamp(Spec::Cancun, timestamp)
    }

    /// Whether Prague is active within the configured boundary.
    #[must_use]
    fn is_prague_active_at_timestamp(&self, timestamp: u64) -> bool {
        self.spec >= Spec::Prague && self.active_at_timestamp(Spec::Prague, timestamp)
    }

    /// Whether Osaka is active within the configured boundary.
    #[must_use]
    fn is_osaka_active_at_timestamp(&self, timestamp: u64) -> bool {
        self.spec >= Spec::Osaka && self.active_at_timestamp(Spec::Osaka, timestamp)
    }

    /// Whether the configured activation timestamp has been reached.
    #[must_use]
    fn active_at_timestamp(&self, spec: Spec, timestamp: u64) -> bool {
        self.hard_forks_timestamps
            .get(&spec)
            .is_some_and(|&activation| timestamp >= activation)
    }
}

#[cfg(test)]
mod tests {
    use super::{ChainSpec, HardForkActivationTime};
    use crate::eips::eip1559::BaseFeeParams;
    use crate::eips::eip7840::BlobParams;
    use crate::eips::eip7892::BlobScheduleBlobParams;
    use crate::spec::Spec;

    const CANCUN_TIMESTAMP: u64 = 100;
    const PRAGUE_TIMESTAMP: u64 = 200;
    const OSAKA_TIMESTAMP: u64 = 300;
    const BPO_TIMESTAMP: u64 = 400;

    fn chain_spec(spec: Spec) -> ChainSpec {
        ChainSpec {
            chain_id: 1,
            spec,
            hard_forks_timestamps: HardForkActivationTime::from([
                (Spec::Cancun, CANCUN_TIMESTAMP),
                (Spec::Prague, PRAGUE_TIMESTAMP),
                (Spec::Osaka, OSAKA_TIMESTAMP),
            ]),
            deposit_contract_address: None,
            base_fee_params: BaseFeeParams::ethereum(),
            blob_schedule: BlobScheduleBlobParams::mainnet()
                .with_scheduled([(BPO_TIMESTAMP, BlobParams::bpo1())]),
        }
    }

    #[test]
    fn timestamp_does_not_advance_past_the_configured_spec() {
        assert_eq!(
            chain_spec(Spec::Cancun).blob_params_at_timestamp(BPO_TIMESTAMP),
            Some(BlobParams::cancun())
        );
        assert_eq!(
            chain_spec(Spec::Prague).blob_params_at_timestamp(BPO_TIMESTAMP),
            Some(BlobParams::prague())
        );
    }

    #[test]
    fn scheduled_blob_params_require_osaka_activation() {
        let osaka = chain_spec(Spec::Osaka);
        assert_eq!(
            osaka.blob_params_at_timestamp(OSAKA_TIMESTAMP),
            Some(BlobParams::osaka())
        );
        assert_eq!(
            osaka.blob_params_at_timestamp(BPO_TIMESTAMP),
            Some(BlobParams::bpo1())
        );
    }

    #[test]
    fn missing_activation_timestamp_fails_closed_for_that_fork() {
        let mut cancun = chain_spec(Spec::Cancun);
        cancun.hard_forks_timestamps.remove(&Spec::Cancun);
        assert_eq!(cancun.blob_params_at_timestamp(BPO_TIMESTAMP), None);
    }

    /// Once `spec` permits every supported fork, timestamps select among them inclusively.
    #[test]
    fn within_the_configured_spec_the_timestamp_picks_the_fork() {
        let osaka = chain_spec(Spec::Osaka);
        for (timestamp, expected) in [
            (CANCUN_TIMESTAMP - 1, None),
            (CANCUN_TIMESTAMP, Some(BlobParams::cancun())),
            (PRAGUE_TIMESTAMP - 1, Some(BlobParams::cancun())),
            (PRAGUE_TIMESTAMP, Some(BlobParams::prague())),
            (OSAKA_TIMESTAMP - 1, Some(BlobParams::prague())),
            (OSAKA_TIMESTAMP, Some(BlobParams::osaka())),
            (BPO_TIMESTAMP - 1, Some(BlobParams::osaka())),
            (BPO_TIMESTAMP, Some(BlobParams::bpo1())),
        ] {
            assert_eq!(
                osaka.blob_params_at_timestamp(timestamp),
                expected,
                "at {timestamp}"
            );
        }
    }

    /// A pre-Cancun boundary disables blob parameters even after every configured timestamp.
    #[test]
    fn a_spec_below_cancun_has_no_blob_market() {
        for spec in [
            Spec::Istanbul,
            Spec::Berlin,
            Spec::London,
            Spec::Merge,
            Spec::Shanghai,
        ] {
            assert_eq!(
                chain_spec(spec).blob_params_at_timestamp(BPO_TIMESTAMP),
                None,
                "{spec:?}"
            );
        }
    }

    /// Missing timestamps skip their fork and fall back to the latest active predecessor.
    #[test]
    fn a_fork_without_an_activation_timestamp_is_skipped_not_fatal() {
        let mut osaka = chain_spec(Spec::Osaka);

        // Without Osaka, its scheduled updates are also unreachable.
        osaka.hard_forks_timestamps.remove(&Spec::Osaka);
        assert_eq!(
            osaka.blob_params_at_timestamp(BPO_TIMESTAMP),
            Some(BlobParams::prague())
        );

        osaka.hard_forks_timestamps.remove(&Spec::Prague);
        assert_eq!(
            osaka.blob_params_at_timestamp(BPO_TIMESTAMP),
            Some(BlobParams::cancun())
        );

        // No Cancun timestamp means no blob market, whatever `spec` permits.
        osaka.hard_forks_timestamps.remove(&Spec::Cancun);
        assert_eq!(osaka.blob_params_at_timestamp(BPO_TIMESTAMP), None);
    }

    /// Two active entries distinguish "latest active" from "first active".
    #[test]
    fn the_latest_active_bpo_entry_wins() {
        let mut osaka = chain_spec(Spec::Osaka);
        osaka.blob_schedule = BlobScheduleBlobParams::mainnet().with_scheduled([
            (BPO_TIMESTAMP, BlobParams::bpo1()),
            (BPO_TIMESTAMP + 100, BlobParams::bpo2()),
        ]);
        for (timestamp, expected) in [
            (BPO_TIMESTAMP - 1, BlobParams::osaka()),
            (BPO_TIMESTAMP, BlobParams::bpo1()),
            (BPO_TIMESTAMP + 99, BlobParams::bpo1()),
            (BPO_TIMESTAMP + 100, BlobParams::bpo2()),
        ] {
            assert_eq!(
                osaka.blob_params_at_timestamp(timestamp),
                Some(expected),
                "at {timestamp}"
            );
        }
    }
}
