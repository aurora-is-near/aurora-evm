// TODO: fix it
#![allow(dead_code)]
use crate::types::Spec;
use aurora_evm::backend::{MemoryAccount, MemoryVicinity};
use primitive_types::{H160, H256, U256};
use std::collections::BTreeMap;

#[derive(Default, Debug, Clone)]
#[cfg_attr(feature = "dump-state", derive(serde::Serialize, serde::Deserialize))]
pub struct StateTestsDump {
    pub state: BTreeMap<H160, MemoryAccount>,
    pub caller: H160,
    pub gas_price: U256,
    pub effective_gas_price: U256,
    pub used_gas: u64,
    pub state_hash: H256,
    pub result_state: BTreeMap<H160, MemoryAccount>,
    pub to: H160,
    pub value: U256,
    pub data: Vec<u8>,
    pub gas_limit: u64,
    pub access_list: Vec<(H160, Vec<H256>)>,
}

pub trait StateTestsDumper {
    fn set_state(&mut self, _state: &BTreeMap<H160, MemoryAccount>) {}
    fn set_used_gas(&mut self, _used_gas: u64) {}
    fn set_vicinity(&mut self, _vicinity: &MemoryVicinity) {}
    fn set_tx_data(
        &mut self,
        _to: H160,
        _value: U256,
        _data: Vec<u8>,
        _gas_limit: u64,
        _access_list: Vec<(H160, Vec<H256>)>,
    ) {
    }
    fn set_state_hash(&mut self, _state_hash: H256) {}
    fn set_result_state(&mut self, _state: &BTreeMap<H160, MemoryAccount>) {}
    fn dump_to_file(&self, _spec: &Spec) {}
}

#[cfg(not(feature = "dump-state"))]
impl StateTestsDumper for StateTestsDump {}

#[cfg(feature = "dump-state")]
impl StateTestsDumper for StateTestsDump {
    fn set_state(&mut self, state: &BTreeMap<H160, MemoryAccount>) {
        self.state = state.clone();
    }

    fn set_used_gas(&mut self, used_gas: u64) {
        self.used_gas = used_gas;
    }

    fn set_vicinity(&mut self, vicinity: &MemoryVicinity) {
        self.caller = vicinity.origin;
        self.gas_price = vicinity.gas_price;
        self.effective_gas_price = vicinity.effective_gas_price;
    }

    fn set_tx_data(
        &mut self,
        to: H160,
        value: U256,
        data: Vec<u8>,
        gas_limit: u64,
        access_list: Vec<(H160, Vec<H256>)>,
    ) {
        self.to = to;
        self.value = value;
        self.data = data;
        self.gas_limit = gas_limit;
        self.access_list = access_list;
    }

    fn set_state_hash(&mut self, state_hash: H256) {
        self.state_hash = state_hash;
    }

    fn set_result_state(&mut self, state: &BTreeMap<H160, MemoryAccount>) {
        self.result_state = state.clone();
    }

    fn dump_to_file(&self, spec: &Spec) {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros();
        let path = format!("state_test_{spec:?}_{now}.json");
        let json = serde_json::to_string(&self).unwrap();
        std::fs::write(path, json).unwrap();
    }
}
