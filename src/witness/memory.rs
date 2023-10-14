use crate::cpu::membus::{NUM_CHANNELS, NUM_GP_CHANNELS};

#[derive(Clone, Copy, Debug)]
pub enum MemoryChannel {
    Code,
    GeneralPurpose(usize),
}

use MemoryChannel::{Code, GeneralPurpose};

//use crate::cpu::kernel::constants::global_metadata::GlobalMetadata;
use crate::memory::segments::Segment;
use crate::witness::errors::MemoryError::{ContextTooLarge, SegmentTooLarge, VirtTooLarge};
use crate::witness::errors::ProgramError;
use crate::witness::errors::ProgramError::MemoryError;

impl MemoryChannel {
    pub fn index(&self) -> usize {
        match *self {
            Code => 0,
            GeneralPurpose(n) => {
                assert!(n < NUM_GP_CHANNELS);
                n + 1
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct MemoryAddress {
    pub(crate) context: usize,
    pub(crate) segment: usize,
    pub(crate) virt: usize,
}

impl MemoryAddress {
    pub(crate) fn new(context: usize, segment: Segment, virt: usize) -> Self {
        Self {
            context,
            segment: segment as usize,
            virt,
        }
    }

    pub(crate) fn new_u256s(context: u32, segment: u32, virt: u32) -> Result<Self, ProgramError> {
        // FIXME range check for context and virt
        if segment >= Segment::COUNT as u32 {
            return Err(MemoryError(SegmentTooLarge { segment }));
        }

        // Calling `as_usize` here is safe as those have been checked above.
        Ok(Self {
            context: context as usize,
            segment: segment as usize,
            virt: virt as usize,
        })
    }

    pub(crate) fn increment(&mut self) {
        self.virt = self.virt.saturating_add(1);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryOpKind {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug)]
pub struct MemoryOp {
    /// true if this is an actual memory operation, or false if it's a padding row.
    pub filter: bool,
    pub timestamp: usize,
    pub address: MemoryAddress,
    pub kind: MemoryOpKind,
    pub value: u32,
}

pub static DUMMY_MEMOP: MemoryOp = MemoryOp {
    filter: false,
    timestamp: 0,
    address: MemoryAddress {
        context: 0,
        segment: 0,
        virt: 0,
    },
    kind: MemoryOpKind::Read,
    value: 0,
};

impl MemoryOp {
    pub fn new(
        channel: MemoryChannel,
        clock: usize,
        address: MemoryAddress,
        kind: MemoryOpKind,
        value: u32,
    ) -> Self {
        let timestamp = clock * NUM_CHANNELS + channel.index();
        MemoryOp {
            filter: true,
            timestamp,
            address,
            kind,
            value,
        }
    }

    pub(crate) fn new_dummy_read(address: MemoryAddress, timestamp: usize, value: u32) -> Self {
        Self {
            filter: false,
            timestamp,
            address,
            kind: MemoryOpKind::Read,
            value,
        }
    }

    pub(crate) fn sorting_key(&self) -> (usize, usize, usize, usize) {
        (
            self.address.context,
            self.address.segment,
            self.address.virt,
            self.timestamp,
        )
    }
}

#[derive(Clone, Debug)]
pub struct MemoryState {
    pub(crate) contexts: Vec<MemoryContextState>,
}

impl MemoryState {
    pub fn new(kernel_code: &[u8]) -> Self {
        let code_u256s = kernel_code.iter().map(|&x| x.into()).collect();
        let mut result = Self::default();
        result.contexts[0].segments[Segment::Code as usize].content = code_u256s;
        result
    }

    pub fn apply_ops(&mut self, ops: &[MemoryOp]) {
        for &op in ops {
            let MemoryOp {
                address,
                kind,
                value,
                ..
            } = op;
            if kind == MemoryOpKind::Write {
                self.set(address, value);
            }
        }
    }

    pub fn get(&self, address: MemoryAddress) -> u32 {
        if address.context >= self.contexts.len() {
            return 0;
        }

        let segment = Segment::all()[address.segment];
        let val = self.contexts[address.context].segments[address.segment].get(address.virt);
        /* FIXME range check
        assert!(
            val.bits() <= segment.bit_range(),
            "Value {} exceeds {:?} range of {} bits",
            val,
            segment,
            segment.bit_range()
        );
        */
        val
    }

    pub fn set(&mut self, address: MemoryAddress, val: u32) {
        while address.context >= self.contexts.len() {
            self.contexts.push(MemoryContextState::default());
        }

        let segment = Segment::all()[address.segment];
        /* FIXME: range check
        assert!(
            val.bits() <= segment.bit_range(),
            "Value {} exceeds {:?} range of {} bits",
            val,
            segment,
            segment.bit_range()
        );
        */
        self.contexts[address.context].segments[address.segment].set(address.virt, val);
    }

    /*
    pub(crate) fn read_global_metadata(&self, field: GlobalMetadata) -> U256 {
        self.get(MemoryAddress::new(
            0,
            Segment::GlobalMetadata,
            field as usize,
        ))
    }
    */
}

impl Default for MemoryState {
    fn default() -> Self {
        Self {
            // We start with an initial context for the kernel.
            contexts: vec![MemoryContextState::default()],
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct MemoryContextState {
    /// The content of each memory segment.
    pub(crate) segments: [MemorySegmentState; Segment::COUNT],
}

impl Default for MemoryContextState {
    fn default() -> Self {
        Self {
            segments: std::array::from_fn(|_| MemorySegmentState::default()),
        }
    }
}

#[derive(Clone, Default, Debug)]
pub(crate) struct MemorySegmentState {
    pub(crate) content: Vec<u32>,
}

impl MemorySegmentState {
    pub(crate) fn get(&self, virtual_addr: usize) -> u32 {
        self.content.get(virtual_addr).copied().unwrap_or(0)
    }

    pub(crate) fn set(&mut self, virtual_addr: usize, value: u32) {
        if virtual_addr >= self.content.len() {
            self.content.resize(virtual_addr + 1, 0);
        }
        self.content[virtual_addr] = value;
    }
}
