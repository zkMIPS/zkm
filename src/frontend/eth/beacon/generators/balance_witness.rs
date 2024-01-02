use std::env;

use serde::{Deserialize, Serialize};

use crate::frontend::hint::simple::hint::Hint;
use crate::frontend::uint::uint64::U64Variable;
use crate::frontend::vars::ValueStream;
use crate::prelude::{ArrayVariable, Bytes32Variable, PlonkParameters};
use crate::utils::eth::beacon::BeaconClient;
use crate::utils::hex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconBalanceWitnessHint {}

impl<L: PlonkParameters<D>, const D: usize> Hint<L, D> for BeaconBalanceWitnessHint {
    fn hint(&self, input_stream: &mut ValueStream<L, D>, output_stream: &mut ValueStream<L, D>) {
        let client = BeaconClient::new(env::var("CONSENSUS_RPC_URL").unwrap());
        let header_root = input_stream.read_value::<Bytes32Variable>();
        let validator_index = input_stream.read_value::<U64Variable>();

        let response = client
            .get_balance_witness(hex!(header_root), validator_index)
            .unwrap();

        output_stream.write_value::<U64Variable>(response);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconBalanceBatchWitnessHint<const B: usize> {}

impl<L: PlonkParameters<D>, const D: usize, const B: usize> Hint<L, D>
    for BeaconBalanceBatchWitnessHint<B>
{
    fn hint(&self, input_stream: &mut ValueStream<L, D>, output_stream: &mut ValueStream<L, D>) {
        let client = BeaconClient::new(env::var("CONSENSUS_RPC_URL").unwrap());
        let header_root = input_stream.read_value::<Bytes32Variable>();
        let start_idx = input_stream.read_value::<U64Variable>();
        let response = client
            .get_balance_batch_witness(hex!(header_root), start_idx, start_idx + B as u64)
            .unwrap();
        output_stream.write_value::<ArrayVariable<U64Variable, B>>(response);
    }
}
