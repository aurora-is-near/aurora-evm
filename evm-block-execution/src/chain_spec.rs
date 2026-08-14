//! Chain configuration and hardfork activation.
//!
//! `Spec` takes precedence over timestamp-based activation: it defines the hardfork this
//! configuration is explicitly bound to. A timestamp alone cannot advance the chain to a newer
//! hardfork, even if that fork's activation time has passed. Moving to a newer hardfork requires
//! explicitly reconfiguring `Spec`; timestamps only determine activation within that boundary.
//!
//! The zkEVM treats this configuration as trusted input and supports Cancun as its minimum
//! hardfork. Activation conditions before Cancun are therefore deliberately not represented here.

use crate::eips::eip1559::BaseFeeParams;
use crate::eips::eip7840::BlobParams;
use crate::eips::eip7892::BlobScheduleBlobParams;
use crate::spec::Spec;
use primitive_types::H160;
use std::collections::BTreeMap;

/// Activation timestamps for the Cancun-and-later hardforks supported by the zkEVM.
pub type HardForkActivationTime = BTreeMap<Spec, u64>;

/// Everything about the chain a block belongs to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainSpec {
    /// EIP-155 chain id.
    pub chain_id: u64,
    /// The trusted hardfork boundary this block is executed under.
    pub spec: Spec,
    /// Activation timestamps for supported timestamp-activated hardforks.
    pub hard_forks_timestamps: HardForkActivationTime,
    /// Block deposit contract address
    pub deposit_contract_address: Option<H160>,
    /// Block base fee
    pub base_fee_params: BaseFeeParams,
    /// Blob-parameter schedule (EIP-7840 / EIP-7892 BPO forks).
    pub blob_schedule: BlobScheduleBlobParams,
}

impl ChainSpec {
    /// The [`BlobParams`] active at `timestamp`, or `None` before Cancun.
    ///
    /// `None` means no supported hardfork within the configured boundary is active, including when
    /// its activation timestamp is missing. A trusted Cancun-and-later configuration therefore gets
    /// `Some`: the latest timestamp-scheduled BPO entry for active Osaka, or the active fork's
    /// default otherwise.
    #[must_use]
    pub fn blob_params_at_timestamp(&self, timestamp: u64) -> Option<BlobParams> {
        // Timestamp-scheduled BPO parameters belong to Osaka and later. Checking them inside the
        // Osaka branch is what prevents a late timestamp from advancing a Cancun/Prague-pinned
        // configuration on its own.
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

    /// Checks whether the Cancun hardfork is active at the given timestamp.
    #[must_use]
    fn is_cancun_active_at_timestamp(&self, timestamp: u64) -> bool {
        self.spec >= Spec::Cancun && self.active_at_timestamp(Spec::Cancun, timestamp)
    }

    /// Checks whether the Prague hardfork is active at the given timestamp.
    #[must_use]
    fn is_prague_active_at_timestamp(&self, timestamp: u64) -> bool {
        self.spec >= Spec::Prague && self.active_at_timestamp(Spec::Prague, timestamp)
    }

    /// Checks whether the Osaka hardfork is active at the given timestamp.
    #[must_use]
    fn is_osaka_active_at_timestamp(&self, timestamp: u64) -> bool {
        self.spec >= Spec::Osaka && self.active_at_timestamp(Spec::Osaka, timestamp)
    }

    /// Checks whether the fork condition is satisfied at the given timestamp.
    ///
    /// This will return false for any condition that is not timestamp-based or activation time unknown.
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

    /// The other half of `timestamp_does_not_advance_past_the_configured_spec`: once `spec` stops
    /// limiting anything, the timestamp alone chooses — and each boundary is inclusive at its own
    /// activation, so every `>=` is checked from both sides.
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

    /// Before Cancun there is no blob market to parameterise, and the boundary alone must say so:
    /// every activation timestamp here is configured and long past.
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

    /// A fork with no activation timestamp cannot activate, but it must not take the chain down with
    /// it: the answer is the newest fork that *can* activate. Removing the entries from the newest
    /// down walks the whole chain, which removing only Cancun's cannot distinguish from a hard stop.
    #[test]
    fn a_fork_without_an_activation_timestamp_is_skipped_not_fatal() {
        let mut osaka = chain_spec(Spec::Osaka);

        // Osaka is out, so the BPO entry goes out of reach with it — scheduled parameters belong to
        // Osaka and later, never to the fork that answers in its place.
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

        // An empty schedule is the fail-closed end of the chain, whatever `spec` claims.
        osaka.hard_forks_timestamps.remove(&Spec::Cancun);
        assert_eq!(osaka.blob_params_at_timestamp(BPO_TIMESTAMP), None);
    }

    /// With one scheduled entry, "latest active wins" is indistinguishable from "first active wins".
    /// Two entries are the smallest case that tells them apart.
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
