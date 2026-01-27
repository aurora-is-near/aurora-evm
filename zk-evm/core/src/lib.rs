use serde::{Deserialize, Serialize};

pub mod spec;
// pub mod transaction;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RawTestCase {
    pub data: String,
}
