//! [EIP-7892] blob-parameter-only fork values and schedules.
//!
//! [EIP-7892]: https://eips.ethereum.org/EIPS/eip-7892

use crate::eips::eip7840::BlobParams;

/// Target blobs per block from BPO1.
pub const BPO1_TARGET_BLOBS_PER_BLOCK: u64 = 10;

/// Maximum blobs per block from BPO1.
pub const BPO1_MAX_BLOBS_PER_BLOCK: u64 = 15;

/// Blob-fee update fraction from BPO1.
pub const BPO1_BASE_UPDATE_FRACTION: u64 = 8_346_193;

/// Target blobs per block from BPO2.
pub const BPO2_TARGET_BLOBS_PER_BLOCK: u64 = 14;

/// Maximum blobs per block from BPO2.
pub const BPO2_MAX_BLOBS_PER_BLOCK: u64 = 21;

/// Blob-fee update fraction from BPO2.
pub const BPO2_BASE_UPDATE_FRACTION: u64 = 11_684_671;

/// Fork defaults and timestamp-scheduled blob-parameter updates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobScheduleBlobParams {
    /// Cancun defaults.
    pub cancun: BlobParams,
    /// Prague defaults.
    pub prague: BlobParams,
    /// Osaka defaults.
    pub osaka: BlobParams,
    /// Timestamp updates from Osaka onward, in any order.
    ///
    /// The latest active timestamp wins; entries may include BPOs and later hardfork parameters.
    pub scheduled: Vec<(u64, BlobParams)>,
}

impl BlobScheduleBlobParams {
    /// Returns the Ethereum mainnet blob schedule.
    #[must_use]
    pub fn mainnet() -> Self {
        Self {
            cancun: BlobParams::cancun(),
            prague: BlobParams::prague(),
            osaka: BlobParams::osaka(),
            scheduled: Vec::default(),
        }
    }

    /// Replaces the timestamp-scheduled entries.
    #[must_use]
    pub fn with_scheduled(
        mut self,
        scheduled: impl IntoIterator<Item = (u64, BlobParams)>,
    ) -> Self {
        self.scheduled = scheduled.into_iter().collect();
        self
    }

    /// Returns the latest scheduled parameters active at `timestamp`, independent of entry order.
    ///
    /// Fork defaults are not searched here.
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

    /// Two BPOs in reverse order prove that lookup does not trust insertion order.
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

    /// Activation boundaries are inclusive; nothing precedes the first entry.
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
