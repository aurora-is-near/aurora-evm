//! Contains constants and helper functions for [EIP-7892](https://github.com/ethereum/EIPs/tree/master/EIPS/eip-7892.md)

use crate::eips::eip7840::BlobParams;

/// Targeted blob count with BPO1 activation
pub const BPO1_TARGET_BLOBS_PER_BLOCK: u64 = 10;

/// Max blob count with BPO1 activation
pub const BPO1_MAX_BLOBS_PER_BLOCK: u64 = 15;

/// Update fraction for BPO1
pub const BPO1_BASE_UPDATE_FRACTION: u64 = 8_346_193;

/// Targeted blob count with BPO2 activation
pub const BPO2_TARGET_BLOBS_PER_BLOCK: u64 = 14;

/// Max blob count with BPO2 activation
pub const BPO2_MAX_BLOBS_PER_BLOCK: u64 = 21;

/// Update fraction for BPO2
pub const BPO2_BASE_UPDATE_FRACTION: u64 = 11_684_671;

/// A scheduled blob parameter update entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlobScheduleEntry {
    /// Blob parameters for the Cancun hardfork
    Cancun(BlobParams),
    /// Blob parameters for the Prague hardfork
    Prague(BlobParams),
    /// Blob parameters that take effect at a specific timestamp
    TimestampUpdate(u64, BlobParams),
}

/// Blob parameters configuration for a chain, including scheduled updates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobScheduleBlobParams {
    /// Configuration for blob-related calculations for the Cancun hardfork.
    pub cancun: BlobParams,
    /// Configuration for blob-related calculations for the Prague hardfork.
    pub prague: BlobParams,
    /// Configuration for blob-related calculations for the Osaka hardfork.
    pub osaka: BlobParams,
    /// All time-based scheduled updates to blob parameters after Osaka.
    ///
    /// This can include blob params for hardforks after Osaka (e.g. Amsterdam) that are interleaved
    /// with BPOs.
    ///
    /// The order is **not** significant: the field is `pub` and the only constructor that fills it
    /// keeps the caller's order, so [`Self::active_scheduled_params_at_timestamp`] picks the latest
    /// active entry rather than trusting a position.
    ///
    /// Caution: it is expected that these are only activated at or after Osaka.
    pub scheduled: Vec<(u64, BlobParams)>,
}

impl BlobScheduleBlobParams {
    /// Returns the blob schedule for the ethereum mainnet.
    #[must_use]
    pub fn mainnet() -> Self {
        Self {
            cancun: BlobParams::cancun(),
            prague: BlobParams::prague(),
            osaka: BlobParams::osaka(),
            scheduled: Vec::default(),
        }
    }

    /// Configures the scheduled [`BlobParams`] with timestamps.
    #[must_use]
    pub fn with_scheduled(
        mut self,
        scheduled: impl IntoIterator<Item = (u64, BlobParams)>,
    ) -> Self {
        self.scheduled = scheduled.into_iter().collect();
        self
    }

    /// Returns the latest blob parameters already active at `timestamp`.
    ///
    /// Chosen by activation timestamp, not by position: [`Self::scheduled`] is a `pub` field and
    /// [`Self::with_scheduled`] keeps whatever order it is handed, so reading the last active *entry*
    /// would hand back an older parameter set for an unsorted schedule — and blob fees and the
    /// per-block blob limit are validated against it. For a schedule in ascending order the two agree.
    ///
    /// Note: this scans only the entries scheduled by timestamp, not cancun or prague.
    #[must_use]
    pub fn active_scheduled_params_at_timestamp(&self, timestamp: u64) -> Option<&BlobParams> {
        self.scheduled
            .iter()
            .filter(|(activation, _)| timestamp >= *activation)
            .max_by_key(|(activation, _)| *activation)
            .map(|(_, params)| params)
    }

    /// Returns the configured Cancun [`BlobParams`].
    #[must_use]
    pub const fn cancun(&self) -> &BlobParams {
        &self.cancun
    }

    /// Returns the configured Prague [`BlobParams`].
    #[must_use]
    pub const fn prague(&self) -> &BlobParams {
        &self.prague
    }

    /// Returns the configured Osaka [`BlobParams`].
    #[must_use]
    pub const fn osaka(&self) -> &BlobParams {
        &self.osaka
    }
}

impl Default for BlobScheduleBlobParams {
    fn default() -> Self {
        Self::mainnet()
    }
}

#[cfg(test)]
mod tests {
    use super::{BlobParams, BlobScheduleBlobParams};

    /// The two BPOs, deliberately handed over newest-first — the order a caller has no obligation to
    /// get right, since the field is `pub` and the setter does not sort.
    fn unordered() -> BlobScheduleBlobParams {
        BlobScheduleBlobParams::mainnet()
            .with_scheduled([(200, BlobParams::bpo2()), (100, BlobParams::bpo1())])
    }

    #[test]
    fn the_latest_active_entry_wins_whatever_the_order() {
        let ordered = BlobScheduleBlobParams::mainnet()
            .with_scheduled([(100, BlobParams::bpo1()), (200, BlobParams::bpo2())]);
        for timestamp in [0, 99, 100, 101, 199, 200, 201, u64::MAX] {
            assert_eq!(
                unordered().active_scheduled_params_at_timestamp(timestamp),
                ordered.active_scheduled_params_at_timestamp(timestamp),
                "timestamp {timestamp}"
            );
        }
    }

    /// The boundaries themselves: activation is inclusive, and nothing is active before the first.
    #[test]
    fn activation_is_inclusive_and_starts_empty() {
        let schedule = unordered();
        assert_eq!(schedule.active_scheduled_params_at_timestamp(99), None);
        assert_eq!(
            schedule.active_scheduled_params_at_timestamp(100),
            Some(&BlobParams::bpo1())
        );
        assert_eq!(
            schedule.active_scheduled_params_at_timestamp(199),
            Some(&BlobParams::bpo1())
        );
        assert_eq!(
            schedule.active_scheduled_params_at_timestamp(200),
            Some(&BlobParams::bpo2())
        );
    }

    #[test]
    fn an_empty_schedule_has_nothing_active() {
        let schedule = BlobScheduleBlobParams::mainnet();
        assert!(schedule.scheduled.is_empty());
        assert_eq!(
            schedule.active_scheduled_params_at_timestamp(u64::MAX),
            None
        );
    }
}
