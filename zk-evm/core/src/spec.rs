use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Spec {
    /// Frontier hard fork
    /// Activated at block 0
    Frontier,
    /// Homestead hard fork
    /// Activated at block 1150000
    Homestead,
    /// Tangerine Whistle hard fork
    /// Activated at block 2463000
    Tangerine,
    /// Spurious Dragon hard fork
    /// Activated at block 2675000
    SpuriousDragon,
    /// Byzantium hard fork
    /// Activated at block 4370000
    Byzantium,
    /// Constantinople hard fork
    /// Activated at block 7280000 is overwritten with PETERSBURG
    Constantinople,
    /// Petersburg hard fork
    /// Activated at block 7280000
    Petersburg,
    /// Istanbul hard fork
    /// Activated at block 9069000
    Istanbul,
    /// Berlin hard fork
    /// Activated at block 12244000
    Berlin,
    /// London hard fork
    /// Activated at block 12965000
    London,
    /// Paris/Merge hard fork
    /// Activated at block 15537394 (TTD: 58750000000000000000000)
    Merge,
    /// Shanghai hard fork
    /// Activated at block 17034870 (Timestamp: 1681338455)
    Shanghai,
    /// Cancun hard fork
    /// Activated at block 19426587 (Timestamp: 1710338135)
    Cancun,
    /// Prague hard fork
    /// Activated at block 22431084 (Timestamp: 1746612311)
    Prague,
    /// Osaka hard fork
    /// Activated at block TBD
    Osaka,
}
