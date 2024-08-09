#![no_std]
#![no_main]

use revm::{
    db::CacheState,
    interpreter::CreateScheme,
    primitives::{calc_excess_blob_gas, keccak256, Bytecode, Env, SpecId, TransactTo, U256},
    Evm,
};
extern crate libc;

use models::*;

mod utils;

use utils::recover_address;

extern crate alloc;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;

zkm_runtime::entrypoint!(main);

pub fn main() {
    ethereum_test();
}

fn ethereum_test() {
    let input: Vec<u8> = zkm_runtime::io::read();
    let suite = read_suite(&input);

    assert!(execute_test_suite(suite).is_ok());
}

fn read_suite(s: &Vec<u8>) -> TestSuite {
    let suite: TestUnit = serde_json::from_slice(s).map_err(|e| e).unwrap();
    let mut btm = BTreeMap::new();
    btm.insert("test".to_string(), suite);
    TestSuite(btm)
}

fn execute_test_suite(suite: TestSuite) -> Result<(), String> {
    for (_name, unit) in suite.0 {
        // Create database and insert cache
        let mut cache_state = CacheState::new(false);
        for (address, info) in unit.pre {
            let acc_info = revm::primitives::AccountInfo {
                balance: info.balance,
                code_hash: keccak256(&info.code),
                code: Some(Bytecode::new_raw(info.code)),
                nonce: info.nonce,
            };
            cache_state.insert_account_with_storage(address, acc_info, info.storage);
        }

        let mut env = Env::default();
        // for mainnet
        env.cfg.chain_id = 1;
        // env.cfg.spec_id is set down the road

        // block env
        env.block.number = unit.env.current_number;
        env.block.coinbase = unit.env.current_coinbase;
        env.block.timestamp = unit.env.current_timestamp;
        env.block.gas_limit = unit.env.current_gas_limit;
        env.block.basefee = unit.env.current_base_fee.unwrap_or_default();
        env.block.difficulty = unit.env.current_difficulty;
        // after the Merge prevrandao replaces mix_hash field in block and replaced difficulty opcode in EVM.
        env.block.prevrandao = unit.env.current_random;
        // EIP-4844
        if let (Some(parent_blob_gas_used), Some(parent_excess_blob_gas)) = (
            unit.env.parent_blob_gas_used,
            unit.env.parent_excess_blob_gas,
        ) {
            env.block
                .set_blob_excess_gas_and_price(calc_excess_blob_gas(
                    parent_blob_gas_used.to(),
                    parent_excess_blob_gas.to(),
                ));
        }

        // tx env
        env.tx.caller = match unit.transaction.sender {
            Some(address) => address,
            _ => recover_address(unit.transaction.secret_key.as_slice())
                .ok_or_else(|| String::new())?,
        };
        env.tx.gas_price = unit
            .transaction
            .gas_price
            .or(unit.transaction.max_fee_per_gas)
            .unwrap_or_default();
        env.tx.gas_priority_fee = unit.transaction.max_priority_fee_per_gas;
        // EIP-4844
        env.tx.blob_hashes = unit.transaction.blob_versioned_hashes;
        env.tx.max_fee_per_blob_gas = unit.transaction.max_fee_per_blob_gas;

        // post and execution
        for (spec_name, tests) in unit.post {
            if matches!(
                spec_name,
                SpecName::ByzantiumToConstantinopleAt5
                    | SpecName::Constantinople
                    | SpecName::Unknown
            ) {
                continue;
            }

            let spec_id = spec_name.to_spec_id();

            for (_index, test) in tests.into_iter().enumerate() {
                env.tx.gas_limit = unit.transaction.gas_limit[test.indexes.gas].saturating_to();

                env.tx.data = unit
                    .transaction
                    .data
                    .get(test.indexes.data)
                    .unwrap()
                    .clone();
                env.tx.value = unit.transaction.value[test.indexes.value];

                env.tx.access_list = unit
                    .transaction
                    .access_lists
                    .get(test.indexes.data)
                    .and_then(Option::as_deref)
                    .unwrap_or_default()
                    .iter()
                    .map(|item| {
                        (
                            item.address,
                            item.storage_keys
                                .iter()
                                .map(|key| U256::from_be_bytes(key.0))
                                .collect::<Vec<_>>(),
                        )
                    })
                    .collect();

                let to = match unit.transaction.to {
                    Some(add) => TransactTo::Call(add),
                    None => TransactTo::Create(CreateScheme::Create),
                };
                env.tx.transact_to = to;

                let mut cache = cache_state.clone();
                cache.set_state_clear_flag(SpecId::enabled(
                    spec_id,
                    revm::primitives::SpecId::SPURIOUS_DRAGON,
                ));
                let mut state = revm::db::State::builder()
                    .with_cached_prestate(cache)
                    .with_bundle_update()
                    .build();
                let mut evm = Evm::builder()
                    .with_db(&mut state)
                    .modify_env(|e| *e = env.clone())
                    .spec_id(spec_id)
                    .build();

                // do the deed
                //let timer = Instant::now();
                let mut check = || {
                    let exec_result = evm.transact_commit();

                    match (&test.expect_exception, &exec_result) {
                        // do nothing
                        (None, Ok(_)) => (),
                        // return okay, exception is expected.
                        (Some(_), Err(_e)) => {
                            return Ok(());
                        }
                        _ => {
                            let s = exec_result.clone().err().map(|e| e.to_string()).unwrap();
                            return Err(s);
                        }
                    }
                    Ok(())
                };

                let Err(e) = check() else { continue };

                return Err(e);
            }
        }
    }
    Ok(())
}
