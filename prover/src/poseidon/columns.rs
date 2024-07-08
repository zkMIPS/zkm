use crate::poseidon::constants::{HALF_N_FULL_ROUNDS, SPONGE_WIDTH};
use plonky2::hash::poseidon::N_PARTIAL_ROUNDS;
pub const FILTER: usize = 0;
const START_IN: usize = FILTER + 1;
pub const fn reg_in(i: usize) -> usize {
    debug_assert!(i < SPONGE_WIDTH);
    START_IN + i
}

const START_OUT: usize = START_IN + SPONGE_WIDTH;
pub const fn reg_out(i: usize) -> usize {
    debug_assert!(i < SPONGE_WIDTH);
    START_OUT + i
}

pub(crate) const TIMESTAMP: usize = START_OUT + SPONGE_WIDTH;

const START_FULL_0: usize = TIMESTAMP + 1;
// full round sbox intermediate
pub const fn reg_full0_s0(round: usize, i: usize) -> usize {
    debug_assert!(i < SPONGE_WIDTH);
    debug_assert!(round < HALF_N_FULL_ROUNDS);

    START_FULL_0 + SPONGE_WIDTH * 2 * round + 2 * i
}

// full round sbox out
pub const fn reg_full0_s1(round: usize, i: usize) -> usize {
    reg_full0_s0(round, i) + 1
}

const START_PARTIAL: usize = START_FULL_0 + SPONGE_WIDTH * 2 * HALF_N_FULL_ROUNDS;
pub const fn reg_partial_s0(round: usize) -> usize {
    debug_assert!(round < N_PARTIAL_ROUNDS);
    START_PARTIAL + round * 2
}
pub const fn reg_partial_s1(round: usize) -> usize {
    reg_partial_s0(round) + 1
}

const START_FULL_1: usize = START_PARTIAL + N_PARTIAL_ROUNDS * 2;

pub const fn reg_full1_s0(round: usize, i: usize) -> usize {
    debug_assert!(i < SPONGE_WIDTH);
    debug_assert!(round < HALF_N_FULL_ROUNDS);

    START_FULL_1 + SPONGE_WIDTH * 2 * round + 2 * i
}

pub const fn reg_full1_s1(round: usize, i: usize) -> usize {
    reg_full1_s0(round, i) + 1
}

pub(crate) const NUM_COLUMNS: usize = START_FULL_1 + SPONGE_WIDTH * 2 * HALF_N_FULL_ROUNDS;

#[test]
fn test_cols() {
    println!("first full rounds.");
    for i in 0..HALF_N_FULL_ROUNDS {
        for j in 0..SPONGE_WIDTH {
            println!("{}", reg_full0_s0(i, j));
            println!("{}", reg_full0_s1(i, j));
        }
    }
    println!("partial rounds.");
    for i in 0..N_PARTIAL_ROUNDS {
        println!("{}", reg_partial_s0(i));
        println!("{}", reg_partial_s1(i));
    }
    println!("last full rounds.");
    for i in 0..HALF_N_FULL_ROUNDS {
        for j in 0..SPONGE_WIDTH {
            println!("{}", reg_full1_s0(i, j));
            println!("{}", reg_full1_s1(i, j));
        }
    }
}
