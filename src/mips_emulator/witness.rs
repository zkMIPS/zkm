use crate::mips_emulator::state::State;
use std::io::Read;

const MIPS_INSTRUCTION_LEN: usize = 32;
const MIPS_REGISTERS_NUM: usize = 32;
const HASH_OUTPUT_TAKE_LEN: usize = 250;
const HASH_CHUNK_LEN: usize = 60;

/// Convert a u64 `integer` to a bit array with length `NUM_BITS`.
/// The bit array will be arranged from low to high.
/// For example, given `integer` 234 and `NUM_BITS` 8
/// The binary representation is '0b11101010', the returned value will be
/// `[0, 1, 0, 1, 0, 1, 1, 1]`
pub fn i2lebsp<const NUM_BITS: usize>(int: u64) -> [bool; NUM_BITS] {
    /// Takes in an FnMut closure and returns a constant-length array with elements of
    /// type `Output`.
    fn gen_const_array<Output: Copy + Default, const LEN: usize>(
        closure: impl FnMut(usize) -> Output,
    ) -> [Output; LEN] {
        let mut ret: [Output; LEN] = [Default::default(); LEN];
        for (bit, val) in ret.iter_mut().zip((0..LEN).map(closure)) {
            *bit = val;
        }
        ret
    }
    assert!(NUM_BITS <= 64);
    gen_const_array(|mask: usize| (int & (1 << mask)) != 0)
}

/// MIPS Instruction, it is fixed length, i.e., 32-bits.
#[derive(Default, Copy, Clone, Debug)]
pub struct Instruction {
    pub addr: u32,
    pub bytecode: u32,
}

impl Instruction {
    fn to_bits(&self) -> [bool; MIPS_INSTRUCTION_LEN] {
        i2lebsp::<MIPS_INSTRUCTION_LEN>(self.bytecode as u64) // omit the high 4 bits of address
    }
}

/// ProgramSegment is a segment of program, it contains the start address and size of
/// the segment, and all the instructions in the segment.
#[derive(Default, Clone)]
pub struct ProgramSegment {
    pub start_addr: u32,
    pub segment_size: u32,
    pub instructions: Vec<Instruction>,
}

/// The program struct consists of all the segments.
/// The `cur_segment`, `cur_instruction`, `cur_bit` variable are used to
/// iterate the instructions of the program, to compute the program hash.
#[derive(Default, Clone)]
pub struct Program {
    cur_segment: usize,
    cur_instruction: usize,
    cur_bit: usize, // each instruction has 32 bits
    pub segments: Vec<ProgramSegment>,
}

/// To initialize the Sinsemilla hasher, it is a math parameter.
pub const PERSONALIZATION: &str = "zkMIPS-CRH";

impl Iterator for Program {
    type Item = bool;

    fn next(&mut self) -> Option<Self::Item> {
        let cur_segment = self.cur_segment;
        let cur_instruction = self.cur_instruction;
        let cur_bit = self.cur_bit;

        let res = if cur_segment >= self.segments.len() {
            None
        } else {
            let ins = self.segments[cur_segment].instructions[cur_instruction];
            let bit = ins.to_bits()[cur_bit];

            self.cur_bit += 1;
            if self.cur_bit == MIPS_INSTRUCTION_LEN {
                self.cur_bit = 0;
                self.cur_instruction += 1;
                if self.cur_instruction == self.segments[cur_segment].instructions.len() {
                    self.cur_instruction = 0;
                    self.cur_segment += 1;
                }
            }
            Some(bit)
        };

        res
    }
}

impl Program {
    pub fn new() -> Self {
        Self {
            cur_segment: 0,
            cur_instruction: 0,
            cur_bit: 0,
            segments: vec![],
        }
    }

    pub fn load_instructions(&mut self, state: &mut Box<State>) {
        for i in 0..self.segments.len() {
            let segment = &mut self.segments[i];
            let mut buf = Vec::<u8>::new();
            state
                .memory
                .read_memory_range(segment.start_addr, segment.segment_size);
            state.memory.read_to_end(&mut buf).unwrap();

            // Here we assume instructions aligned with 4 bytes, this is reasonable, because
            // the MIPS instruction is fixed length with 4 bytes.
            // Note here we may read some data segments into the Program struct, it is ok, because
            // we use program to compute hash for integrity and load the program to halo2 table for
            // instruction lookup, load data segments won't have effect.
            for i in (0..buf.len()).step_by(4) {
                segment.instructions.push(Instruction {
                    addr: segment.start_addr + (i as u32),
                    bytecode: u32::from_le_bytes(buf[i..i + 4].try_into().unwrap()),
                });
            }
        }
    }

    pub fn reset_iterator(&mut self) {
        self.cur_segment = 0;
        self.cur_instruction = 0;
        self.cur_bit = 0;
    }

    pub fn total_instructions(&self) -> usize {
        let mut sum = 0;
        for i in 0..self.segments.len() {
            sum += self.segments[i].instructions.len();
        }
        sum
    }

    /// Fetch the next instruction, it is different the Iterator trait cause next method get
    /// a single bit of instruction, the `next_instruction` method gets the next instruction
    /// with 4 bytes.
    /// `cur_segment` and `cur_instruction` variable are passed in. The method also returns
    /// the updated `cur_segment` and `cur_instruction` as `res_segment` and `res_instruction`.
    /// If read to the end, then the method returns `None`, otherwise returns `Instruction`.
    /// The method has side effect: changing iterator variables, after using
    /// should invoke `reset_iterator`.
    pub fn next_instruction(
        &self,
        cur_segment: usize,
        cur_instruction: usize,
    ) -> (Option<Instruction>, usize, usize) {
        let mut res_segment = cur_segment;
        let mut res_instruction = cur_instruction;

        let res = if res_segment >= self.segments.len() {
            (None, res_segment, res_instruction)
        } else {
            let ins = self.segments[res_segment].instructions[res_instruction];

            res_instruction += 1;
            if res_instruction == self.segments[res_segment].instructions.len() {
                res_instruction = 0;
                res_segment += 1;
            }

            (Some(ins), res_segment, res_instruction)
        };

        res
    }
}
