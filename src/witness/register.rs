use crate::cpu::membus::{NUM_CHANNELS, NUM_REG_CHANNELS};

#[derive(Clone, Copy, Debug)]
pub enum RegChannel {
    GeneralPurpose(usize),
}

use RegChannel::GeneralPurpose;

//use crate::cpu::kernel::constants::global_metadata::GlobalMetadata;
use crate::witness::errors::ProgramError;
use crate::witness::errors::ProgramError::InvalidRegister;

impl RegChannel {
    pub fn index(&self) -> usize {
        match *self {
            GeneralPurpose(n) => {
                assert!(n < NUM_REG_CHANNELS);
                n
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegOpKind {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug)]
pub struct RegOp {
    /// true if this is an actual memory operation, or false if it's a padding row.
    pub filter: bool,
    pub timestamp: usize,
    pub index: u8,
    pub kind: RegOpKind,
    pub value: u32,
}

pub static DUMMY_REGOP: RegOp = RegOp {
    filter: false,
    timestamp: 0,
    index: 0,
    kind: RegOpKind::Read,
    value: 0,
};

impl RegOp {
    pub fn new(
        channel: RegChannel,
        clock: usize,
        index: u8,
        kind: RegOpKind,
        value: u32,
    ) -> Self {
        let timestamp = clock * NUM_CHANNELS + channel.index();
        RegOp {
            filter: true,
            timestamp,
            index,
            kind,
            value,
        }
    }

    pub(crate) fn new_dummy_read(index: u8, timestamp: usize, value: u32) -> Self {
        Self {
            filter: false,
            timestamp,
            index,
            kind: RegOpKind::Read,
            value,
        }
    }

    pub(crate) fn sorting_key(&self) -> (usize, usize) {
        (
            self.index as usize,
            self.timestamp,
        )
    }
}
