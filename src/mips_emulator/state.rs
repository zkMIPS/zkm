use crate::mips_emulator::memory::Memory;
use crate::mips_emulator::page::{PAGE_ADDR_MASK, PAGE_SIZE};
use crate::mips_emulator::witness::{Program, ProgramSegment};
use elf::abi::PT_LOAD;
use elf::endian::AnyEndian;
use log::{trace, warn};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::fs;
use std::io::{stderr, stdout, Write};
use std::path::Path;

pub const FD_STDIN: u32 = 0;
pub const FD_STDOUT: u32 = 1;
pub const FD_STDERR: u32 = 2;
pub const MIPS_EBADF: u32 = 9;

pub const SEGMENT_STEPS: usize = 200000;

// image_id = keccak(page_hash_root || end_pc)
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone, Default)]
pub struct Segment {
    pub mem_image: BTreeMap<u32, u32>,
    pub pc: u32,
    pub segment_id: u32,
    pub pre_image_id: [u8; 32],
    pub pre_hash_root: [u8; 32],
    pub image_id: [u8; 32],
    pub page_hash_root: [u8; 32],
    pub end_pc: u32,
}

pub struct State {
    pub memory: Box<Memory>,

    /// the 32 general purpose registers of MIPS.
    pub registers: [u32; 32],
    /// the pc register stores the current execution instruction address.
    pub pc: u32,
    /// the next pc stores the next execution instruction address.
    next_pc: u32,
    /// the hi register stores the multiplier/divider result high(remainder) part.
    hi: u32,
    /// the low register stores the multiplier/divider result low(quotient) part.
    lo: u32,

    /// heap handles the mmap syscall.
    heap: u32,
    /// step tracks the total step has been executed.
    step: u64,

    pub exited: bool,
    exit_code: u8,
}

impl Display for State {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "State {{ \n pc: 0x{:x}, next_pc: 0x{:x}, hi: {}, lo: {}, heap: 0x{:x}, step: {}, exited: {}, \
            \n registers: {:?} \
            \n memory: {} \n}}",
            self.pc, self.next_pc, self.hi, self.lo, self.heap, self.step, self.exited, self.registers, self.memory.usage()
        )
    }
}

impl State {
    pub fn new() -> Box<Self> {
        Box::new(Self {
            memory: Box::new(Memory::new()),
            registers: Default::default(),
            pc: 0,
            next_pc: 4,
            hi: 0,
            lo: 0,
            heap: 0,
            step: 0,
            exited: false,
            exit_code: 0,
        })
    }

    pub fn load_elf(f: &elf::ElfBytes<AnyEndian>) -> (Box<Self>, Box<Program>) {
        let mut s = Box::new(Self {
            memory: Box::new(Memory::new()),
            registers: Default::default(),

            pc: f.ehdr.e_entry as u32,
            next_pc: f.ehdr.e_entry as u32 + 4,

            hi: 0,
            lo: 0,
            heap: 0x20000000,
            step: 0,
            exited: false,
            exit_code: 0,
        });

        let mut program = Box::from(Program::new());

        let segments = f
            .segments()
            .expect("invalid ELF cause failed to parse segments.");
        for segment in segments {
            if segment.p_type == 0x70000003 {
                continue;
            }

            let r = f
                .segment_data(&segment)
                .expect("failed to parse segment data");
            let mut r = Vec::from(r);

            if segment.p_filesz != segment.p_memsz {
                if segment.p_type == PT_LOAD {
                    if segment.p_filesz < segment.p_memsz {
                        let diff = (segment.p_memsz - segment.p_filesz) as usize;
                        r.extend_from_slice(vec![0u8; diff].as_slice());
                    } else {
                        panic!(
                            "invalid PT_LOAD program segment, file size ({}) > mem size ({})",
                            segment.p_filesz, segment.p_memsz
                        );
                    }
                } else {
                    panic!("has different file size ({}) than mem size ({}): filling for non PT_LOAD segments is not supported",
                           segment.p_filesz, segment.p_memsz);
                }
            }

            if segment.p_vaddr + segment.p_memsz >= 1u64 << 32 {
                panic!(
                    "program %d out of 32-bit mem range: {:x} -{:x} (size: {:x})",
                    segment.p_vaddr, segment.p_memsz, segment.p_memsz
                );
            }

            let n = r.len();
            let r: Box<&[u8]> = Box::new(r.as_slice());
            s.memory
                .set_memory_range(segment.p_vaddr as u32, r)
                .expect("failed to set memory range");

            if n != 0 {
                program.segments.push(ProgramSegment {
                    start_addr: segment.p_vaddr as u32,
                    segment_size: n as u32,
                    instructions: vec![],
                })
            }
        }
        (s, program)
    }

    pub fn patch_go(&mut self, f: &elf::ElfBytes<AnyEndian>) {
        let symbols = f
            .symbol_table()
            .expect("failed to read symbols table, cannot patch program")
            .expect("failed to parse symbols table, cannot patch program");

        for symbol in symbols.0 {
            match symbols.1.get(symbol.st_name as usize) {
                Ok(name) => match name {
                    "runtime.gcenable"
                    | "runtime.init.5"
                    | "runtime.main.func1"
                    | "runtime.deductSweepCredit"
                    | "runtime.(*gcControllerState).commit"
                    | "github.com/prometheus/client_golang/prometheus.init"
                    | "github.com/prometheus/client_golang/prometheus.init.0"
                    | "github.com/prometheus/procfs.init"
                    | "github.com/prometheus/common/model.init"
                    | "github.com/prometheus/client_model/go.init"
                    | "github.com/prometheus/client_model/go.init.0"
                    | "github.com/prometheus/client_model/go.init.1"
                    | "flag.init"
                    | "runtime.check" => {
                        let r: Vec<u8> = vec![0x03, 0xe0, 0x00, 0x08, 0, 0, 0, 0];
                        let r = Box::new(r.as_slice());
                        self.memory
                            .set_memory_range(symbol.st_value as u32, r)
                            .expect("set memory range failed");
                    }
                    "runtime.MemProfileRate" => {
                        let r: Vec<u8> = vec![0, 0, 0, 0];
                        let r = Box::new(r.as_slice());
                        self.memory
                            .set_memory_range(symbol.st_value as u32, r)
                            .expect("set memory range failed");
                    }
                    _ => {}
                },
                Err(e) => {
                    warn!("parse symbol failed, {}", e);
                    continue;
                }
            }
        }
    }

    pub fn patch_stack(&mut self, input: &str) {
        // setup stack pointer
        let sp: u32 = 0x7fFFd000;

        // allocate 1 page for the initial stack data, and 16kb = 4 pages for the stack to grow
        let r: Vec<u8> = vec![0; 5 * PAGE_SIZE];
        let r: Box<&[u8]> = Box::new(r.as_slice());

        let addr = sp - 4 * PAGE_SIZE as u32;
        self.memory
            .set_memory_range(addr, r)
            .expect("failed to set memory range");

        self.registers[29] = sp;

        let mut store_mem = |addr: u32, v: u32| {
            let mut dat = [0u8; 4];
            dat.copy_from_slice(&v.to_be_bytes());
            let r = Box::new(dat.as_slice());
            self.memory
                .set_memory_range(addr, r)
                .expect("failed to set memory range");
        };

        let mut items: BTreeMap<u32, &str> = BTreeMap::new();
        let mut index = 0;
        for item in input.split_whitespace() {
            items.insert(index, item);
            index += 1u32;
        }

        println!("count {} items {:?}", index, items);
        // init argc,  argv, aux on stack
        store_mem(sp, index);
        store_mem(sp + 4 * (index + 1), 0x35); // argv[n] = 0 (terminating argv)
        store_mem(sp + 4 * (index + 2), 0x00); // envp[term] = 0 (no env vars)
        store_mem(sp + 4 * (index + 3), 0x06); // auxv[0] = _AT_PAGESZ = 6 (key)
        store_mem(sp + 4 * (index + 4), 0x1000); // auxv[1] = page size of 4 KiB (value) - (== minPhysPageSize)
        store_mem(sp + 4 * (index + 5), 0x1A); // auxv[2] = AT_RANDOM
        store_mem(sp + 4 * (index + 6), sp + 4 * (index + 8)); // auxv[3] = address of 16 bytes containing random value
        store_mem(sp + 4 * (index + 7), 0); // auxv[term] = 0

        let mut store_mem_str = |paddr: u32, daddr: u32, str: &str| {
            let mut dat = [0u8; 4];
            dat.copy_from_slice(&daddr.to_be_bytes());
            let r = Box::new(dat.as_slice());
            self.memory
                .set_memory_range(paddr, r)
                .expect("failed to set memory range");
            let r = Box::new(str.as_bytes());
            self.memory
                .set_memory_range(daddr, r)
                .expect("failed to set memory range");
        };

        let mut addr = sp + 4 * (index + 12);
        for (ind, inp) in items.iter() {
            let index = *ind;
            store_mem_str(sp + 4 * (index + 1), addr, inp);
            addr += inp.len() as u32 + 1;
        }

        let mut rng = thread_rng();
        let r: [u8; 16] = rng.gen();
        let r: Box<&[u8]> = Box::new(r.as_slice());
        self.memory
            .set_memory_range(sp + 4 * (index + 8), r)
            .expect("failed to set memory range");
    }

    pub fn load_preimage(&mut self, blockpath: String) {
        let mut hash_bytes = [0u8; 32];
        for i in 0..8 {
            hash_bytes[i * 4..i * 4 + 4].copy_from_slice(
                self.memory
                    .get_memory((0x30001000 + i * 4) as u32)
                    .to_be_bytes()
                    .as_ref(),
            )
        }

        let hex_string = hex::encode(hash_bytes);
        let mut preiamge_path = blockpath.clone();
        preiamge_path.push_str("0x");
        preiamge_path.push_str(hex_string.as_str());

        let data = fs::read(preiamge_path).expect("could not read file");
        let data: Box<&[u8]> = Box::new(data.as_slice());

        self.memory.set_memory(0x31000000, data.len() as u32);

        self.memory
            .set_memory_range(0x31000004, data)
            .expect("set memory range failed");
    }

    pub fn load_input(&mut self, blockpath: &str) {
        let input_path = Path::new(blockpath).join("input");

        log::trace!("load input: {:?}", input_path);
        let data = fs::read(input_path).expect("could not read file");
        let data: Box<&[u8]> = Box::new(data.as_slice());

        self.memory
            .set_memory_range(0x30000000, data)
            .expect("set memory range failed");
    }

    pub fn sync_registers(&mut self) {
        for i in 0..32 {
            self.memory.set_memory(i << 2, self.registers[i as usize]);
        }

        self.memory.set_memory(32 << 2, self.lo);
        self.memory.set_memory(33 << 2, self.hi);
        self.memory.set_memory(34 << 2, self.heap);
        self.memory.set_memory(35 << 2, self.pc);
    }
    pub fn load_registers(&mut self) {
        let _ = self.memory.get_memory(0);
    }
}

pub struct InstrumentedState {
    /// state stores the state of the MIPS emulator
    pub state: Box<State>,

    /// writer for stdout
    stdout_writer: Box<dyn Write>,
    /// writer for stderr
    stderr_writer: Box<dyn Write>,

    pre_segment_id: u32,
    pre_pc: u32,
    pre_image_id: [u8; 32],
    pre_hash_root: [u8; 32],
    block_path: String,
}

impl Display for InstrumentedState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "state: {}", self.state,)
    }
}

impl InstrumentedState {
    pub fn new(state: Box<State>, block_path: String) -> Box<Self> {
        Box::new(Self {
            state,
            stdout_writer: Box::new(stdout()),
            stderr_writer: Box::new(stderr()),
            block_path,
            pre_pc: 0u32,
            pre_image_id: [0u8; 32],
            pre_hash_root: [0u8; 32],
            pre_segment_id: 0u32,
        })
    }

    fn handle_syscall(&mut self) {
        let syscall_num = self.state.registers[2]; // v0
        let mut v0 = 0u32;
        let mut v1 = 0u32;

        let a0 = self.state.registers[4];
        let a1 = self.state.registers[5];
        let a2 = self.state.registers[6];

        match syscall_num {
            4020 => {
                //read preimage (getpid)
                self.state.load_preimage(self.block_path.clone())
            }
            4090 => {
                // mmap
                // args: a0 = heap/hint, indicates mmap heap or hint. a1 = size
                let mut size = a1;
                if size & (PAGE_ADDR_MASK as u32) != 0 {
                    // adjust size to align with page size
                    size += PAGE_SIZE as u32 - (size & (PAGE_ADDR_MASK as u32));
                }
                if a0 == 0 {
                    v0 = self.state.heap;
                    self.state.heap += size;
                    trace!("mmap heap {:x?} size {:x?}", v0, size);
                } else {
                    v0 = a0;
                    trace!("mmap hint {:x?} size {:x?}", v0, size);
                }
            }
            4045 => {
                // brk
                v0 = 0x40000000;
            }
            4120 => {
                // clone
                v0 = 1;
            }
            4246 => {
                // exit group
                self.state.exited = true;
                self.state.exit_code = a0 as u8;
            }
            4003 => {
                // read
                // args: a0 = fd, a1 = addr, a2 = count
                // returns: v0 = read, v1 = err code
                match a0 {
                    FD_STDIN => {
                        // leave v0 and v1 zero: read nothing, no error
                    }
                    _ => {
                        v0 = 0xFFffFFff;
                        v1 = MIPS_EBADF;
                    }
                }
            }
            4004 => {
                // write
                // args: a0 = fd, a1 = addr, a2 = count
                // returns: v0 = written, v1 = err code
                match a0 {
                    // todo: track memory read
                    FD_STDOUT => {
                        self.state.memory.read_memory_range(a1, a2);
                        if let Err(e) =
                            std::io::copy(self.state.memory.as_mut(), self.stdout_writer.as_mut())
                        {
                            panic!("read range from memory failed {}", e);
                        }
                        v0 = a2;
                    }
                    FD_STDERR => {
                        self.state.memory.read_memory_range(a1, a2);
                        if let Err(e) =
                            std::io::copy(self.state.memory.as_mut(), self.stderr_writer.as_mut())
                        {
                            panic!("read range from memory failed {}", e);
                        }
                        v0 = a2;
                    }
                    _ => {
                        v0 = 0xFFffFFff;
                        v1 = MIPS_EBADF;
                    }
                }
            }
            4055 => {
                // fcntl
                // args: a0 = fd, a1 = cmd
                if a1 == 3 {
                    // F_GETFL: get file descriptor flags
                    match a0 {
                        FD_STDIN => {
                            v0 = 0 // O_RDONLY
                        }
                        FD_STDOUT | FD_STDERR => {
                            v0 = 1 // O_WRONLY
                        }
                        _ => {
                            v0 = 0xFFffFFff;
                            v1 = MIPS_EBADF;
                        }
                    }
                } else {
                    v0 = 0xFFffFFff;
                    v1 = MIPS_EBADF;
                }
            }
            _ => {}
        }

        self.state.registers[2] = v0;
        self.state.registers[7] = v1;

        self.state.pc = self.state.next_pc;
        self.state.next_pc += 4;
    }

    fn handle_branch(&mut self, opcode: u32, insn: u32, rt_reg: u32, rs: u32) {
        let should_branch = match opcode {
            4 | 5 => {
                // beq/bne
                let rt = self.state.registers[rt_reg as usize];
                (rs == rt && opcode == 4) || (rs != rt && opcode == 5)
            }
            6 => {
                // blez
                (rs as i32) <= 0
            }
            7 => {
                // bgtz
                (rs as i32) > 0
            }
            1 => {
                // reqimm
                let rtv = (insn >> 16) & 0x1F;
                if rtv == 0 {
                    // bltz
                    (rs as i32) < 0
                } else if rtv == 1 {
                    // 1 -> bgez
                    (rs as i32) >= 0
                } else {
                    false
                }
            }
            _ => {
                panic!("invalid branch opcode {}", opcode);
            }
        };

        let prev_pc = self.state.pc;
        if should_branch {
            // then continue with the instruction the branch jumps to.
            self.state.pc =
                (prev_pc as u64 + 4u64 + (sign_extension(insn & 0xFFFF, 16) << 2) as u64) as u32;
        } else {
            self.state.pc = self.state.next_pc + 4;
        }
        self.state.next_pc = self.state.pc + 4;
    }

    fn handle_jump(&mut self, link_reg: u32, dest: u32) {
        let prev_pc = self.state.pc;
        self.state.pc = dest;
        self.state.next_pc = dest + 4;

        if link_reg != 0 {
            // set the link-register to the instr after the delay slot instruction.
            self.state.registers[link_reg as usize] = prev_pc + 8;
        }
    }

    fn handle_hilo(&mut self, fun: u32, rs: u32, rt: u32, store_reg: u32) {
        let mut val = 0u32;
        match fun {
            0x10 => {
                // mfhi
                val = self.state.hi;
            }
            0x11 => {
                // mthi
                self.state.hi = rs;
            }
            0x12 => {
                // mflo
                val = self.state.lo;
            }
            0x13 => {
                // mtlo
                self.state.lo = rs;
            }
            0x18 => {
                // mult
                let acc = (((rs as i32) as i64).wrapping_mul((rt as i32) as i64)) as u64;
                self.state.hi = (acc >> 32) as u32;
                self.state.lo = acc as u32;
            }
            0x19 => {
                // mulu
                let acc = rs as u64 * rt as u64;
                self.state.hi = (acc >> 32) as u32;
                self.state.lo = acc as u32;
            }
            0x1a => {
                // div
                self.state.hi = ((rs as i32) % (rt as i32)) as u32;
                self.state.lo = ((rs as i32) / (rt as i32)) as u32;
            }
            0x1b => {
                // divu
                self.state.hi = rs % rt;
                self.state.lo = rs / rt;
            }
            n => {
                panic!("invalid fun when process hi lo, fun: {}", n);
            }
        }

        if store_reg != 0 {
            self.state.registers[store_reg as usize] = val;
        }

        self.state.pc = self.state.next_pc;
        self.state.next_pc += 4;
    }

    fn handle_rd(&mut self, store_reg: u32, val: u32, conditional: bool) {
        if store_reg >= 32 {
            panic!("invalid register");
        }
        if store_reg != 0 && conditional {
            self.state.registers[store_reg as usize] = val;
        }

        self.state.pc = self.state.next_pc;
        self.state.next_pc += 4;
    }

    // this method executes a single mips instruction
    fn mips_step(&mut self) {
        if self.state.exited {
            return;
        }

        self.state.step += 1;

        // fetch instruction
        let insn = self.state.memory.get_memory(self.state.pc);
        let opcode = insn >> 26; // 6-bits

        // j-type j/jal
        if opcode == 2 || opcode == 3 {
            let link_reg = match opcode {
                3 => 31,
                _ => 0,
            };

            self.handle_jump(link_reg, sign_extension(insn & 0x03ffFFff, 26) << 2);
            return;
        }

        // fetch register
        let mut rt = 0u32;
        let rt_reg = (insn >> 16) & 0x1f;

        // R-type or I-type (stores rt)
        let mut rs = self.state.registers[((insn >> 21) & 0x1f) as usize];
        let mut rd_reg = rt_reg;
        if opcode == 0 || opcode == 0x1c {
            // R-type (stores rd)
            rt = self.state.registers[rt_reg as usize];
            rd_reg = (insn >> 11) & 0x1f;
        } else if opcode < 0x20 {
            // rt is SignExtImm
            // don't sign extend for andi, ori, xori
            if opcode == 0xC || opcode == 0xD || opcode == 0xE {
                // ZeroExtImm
                rt = insn & 0xFFFF;
            } else {
                rt = sign_extension(insn & 0xffFF, 16);
            }
        } else if opcode >= 0x28 || opcode == 0x22 || opcode == 0x26 {
            // store rt value with store
            rt = self.state.registers[rt_reg as usize];

            // store actual rt with lwl and lwr
            rd_reg = rt_reg;
        }

        if (4..8).contains(&opcode) || opcode == 1 {
            self.handle_branch(opcode, insn, rt_reg, rs);
            return;
        }

        let mut store_addr: u32 = 0xffFFffFF;
        // memory fetch (all I-type)
        // we do the load for stores also
        let mut mem: u32 = 0;
        if opcode >= 0x20 {
            // M[R[rs]+SignExtImm]
            rs = (rs as u64 + sign_extension(insn & 0xffFF, 16) as u64) as u32;
            let addr = rs & 0xFFffFFfc;
            mem = self.state.memory.get_memory(addr);
            if opcode >= 0x28 && opcode != 0x30 {
                // store
                store_addr = addr;
                // store opcodes don't write back to a register
                rd_reg = 0;
            }

            /*
            // create the memory access operation
            mem_access = Some(MemoryAccess {
                rw_counter: self.state.step,
                addr,
                op: MemoryOperation::Read,
                value: mem,
                value_prev: mem,
            });
            */
        }

        // ALU
        let val = self.execute(insn, rs, rt, mem);

        let fun = insn & 0x3f; // 6-bits
        if opcode == 0 && (8..0x1c).contains(&fun) {
            if fun == 8 || fun == 9 {
                let link_reg = match fun {
                    9 => rd_reg,
                    _ => 0,
                };

                self.handle_jump(link_reg, rs);
                return;
            }

            if fun == 0xa {
                self.handle_rd(rd_reg, rs, rt == 0);
                return;
            }
            if fun == 0xb {
                self.handle_rd(rd_reg, rs, rt != 0);
                return;
            }

            // syscall (can read/write)
            if fun == 0xc {
                self.handle_syscall();
                // todo: trace the memory access
                return;
            }

            // lo and hi registers
            // can write back
            if (0x10..0x1c).contains(&fun) {
                self.handle_hilo(fun, rs, rt, rd_reg);
                return;
            }
        }

        // stupid sc, write a 1 to rt
        if opcode == 0x38 && rt_reg != 0 {
            self.state.registers[rt_reg as usize] = 1;
        }

        // write memory
        if store_addr != 0xffFFffFF {
            //let value_prev = self.state.memory.get_memory(store_addr);
            self.state.memory.set_memory(store_addr, val);
            /*
            mem_access = Some(MemoryAccess {
                rw_counter: self.state.step,
                addr: store_addr,
                op: MemoryOperation::Write,
                value: val,
                value_prev,
            });
            */
        }

        // write back the value to the destination register
        self.handle_rd(rd_reg, val, true);
    }

    fn execute(&mut self, insn: u32, mut rs: u32, rt: u32, mem: u32) -> u32 {
        // implement alu
        let mut opcode = insn >> 26;
        let mut fun = insn & 0x3F;

        if opcode < 0x20 {
            // transform ArithLogI
            if (8..0xf).contains(&opcode) {
                match opcode {
                    8 => {
                        fun = 0x20; // addi
                    }
                    9 => {
                        fun = 0x21; // addiu
                    }
                    0xa => {
                        fun = 0x2a; // slti
                    }
                    0xb => {
                        fun = 0x2b; // sltiu
                    }
                    0xc => {
                        fun = 0x24; // andi
                    }
                    0xd => {
                        fun = 0x25; // ori
                    }
                    0xe => {
                        fun = 0x26; // xori
                    }
                    _ => {}
                }
                opcode = 0;
            }

            // 0 is opcode SPECIAL
            if opcode == 0 {
                let shamt = (insn >> 6) & 0x1f;
                if fun < 0x20 {
                    if fun >= 0x08 {
                        return rs; // jr/jalr/div + others
                    } else if fun == 0x00 {
                        return rt << shamt; // sll
                    } else if fun == 0x02 {
                        return rt >> shamt; // srl
                    } else if fun == 0x03 {
                        return sign_extension(rt >> shamt, 32 - shamt); // sra
                    } else if fun == 0x04 {
                        return rt << (rs & 0x1f); // sllv
                    } else if fun == 0x06 {
                        return rt >> (rs & 0x1f); // srlv
                    } else if fun == 0x07 {
                        return sign_extension(rt >> rs, 32 - rs); // srav
                    }
                }

                // 0x10 - 0x13 = mfhi, mthi, mflo, mtlo
                // R-type (ArithLog)
                match fun {
                    0x20 | 0x21 => {
                        return (rs as u64 + rt as u64) as u32; // add or addu
                    }
                    0x22 | 0x23 => {
                        return (rs as i64 - rt as i64) as u32; // sub or subu
                    }
                    0x24 => {
                        return rs & rt; // and
                    }
                    0x25 => {
                        return rs | rt; // or
                    }
                    0x26 => {
                        return rs ^ rt; // xor
                    }
                    0x27 => {
                        return !(rs | rt); // nor
                    }
                    0x2a => {
                        return if (rs as i32) < (rt as i32) {
                            1 // slt
                        } else {
                            0
                        };
                    }
                    0x2b => {
                        return if rs < rt {
                            1 // sltu
                        } else {
                            0
                        };
                    }
                    _ => {}
                }
            } else if opcode == 0xf {
                return rt << 16; // lui
            } else if opcode == 0x1c {
                // SPECIAL2
                if fun == 2 {
                    // mul
                    return rs.wrapping_mul(rt);
                }
                if fun == 0x20 || fun == 0x21 {
                    // clo
                    if fun == 0x20 {
                        rs = !rs;
                    }
                    let mut i = 0;
                    while rs & 0x80000000 != 0 {
                        rs <<= 1;
                        i += 1;
                    }
                    return i;
                }
            }
        } else if opcode < 0x28 {
            match opcode {
                0x20 => {
                    // lb
                    return sign_extension((mem >> (24 - (rs & 3) * 8)) & 0xff, 8);
                }
                0x21 => {
                    // lh
                    return sign_extension((mem >> (16 - (rs & 2) * 8)) & 0xffff, 16);
                }
                0x22 => {
                    // lwl
                    let val = mem << ((rs & 3) * 8);
                    let mask = 0xffFFffFFu32 << ((rs & 3) * 8);
                    return (rt & (!mask)) | val;
                }
                0x23 => {
                    // lw
                    return mem;
                }
                0x24 => {
                    // lbu
                    return (mem >> (24 - (rs & 3) * 8)) & 0xff;
                }
                0x25 => {
                    // lhu
                    return (mem >> (16 - (rs & 2) * 8)) & 0xffff;
                }
                0x26 => {
                    // lwr
                    let val = mem >> (24 - (rs & 3) * 8);
                    let mask = 0xffFFffFFu32 >> (24 - (rs & 3) * 8);
                    return (rt & (!mask)) | val;
                }
                _ => {}
            }
        } else if opcode == 0x28 {
            // sb
            let val = (rt & 0xff) << (24 - (rs & 3) * 8);
            let mask = 0xffFFffFFu32 ^ (0xff << (24 - (rs & 3) * 8));
            return (mem & mask) | val;
        } else if opcode == 0x29 {
            // sh
            let val = (rt & 0xffff) << (16 - (rs & 2) * 8);
            let mask = 0xffFFffFFu32 ^ (0xffff << (16 - (rs & 2) * 8));
            return (mem & mask) | val;
        } else if opcode == 0x2a {
            // swl
            let val = rt >> ((rs & 3) * 8);
            let mask = 0xffFFffFFu32 >> ((rs & 3) * 8);
            return (mem & (!mask)) | val;
        } else if opcode == 0x2b {
            // sw
            return rt;
        } else if opcode == 0x2e {
            // swr
            let val = rt << (24 - (rs & 3) * 8);
            let mask = 0xffFFffFFu32 << (24 - (rs & 3) * 8);
            return (mem & (!mask)) | val;
        } else if opcode == 0x30 {
            // ll
            return mem;
        } else if opcode == 0x38 {
            // sc
            return rt;
        }

        panic!("invalid instruction, opcode: {}", opcode);
    }

    pub fn step(&mut self) {
        self.mips_step()
    }

    /// the caller should provide a write to write segemnt if proof is true
    pub fn split_segment<W: Write>(
        &mut self,
        proof: bool,
        output: &str,
        new_writer: fn(&str) -> Option<W>,
    ) {
        self.state.sync_registers();
        let (image_id, page_hash_root) = self.state.memory.compute_image_id(self.state.pc);
        let image = self.state.memory.get_input_image();

        if proof {
            let segment = Segment {
                mem_image: image,
                segment_id: self.pre_segment_id,
                pc: self.pre_pc,
                pre_hash_root: self.pre_hash_root,
                pre_image_id: self.pre_image_id,
                image_id,
                end_pc: self.state.pc,
                page_hash_root,
            };
            let name = format!("{output}/{}", self.pre_segment_id);
            log::trace!("split: file {}", name);
            let mut f = new_writer(&name).unwrap();
            let data = serde_json::to_vec(&segment).unwrap();
            f.write_all(data.as_slice()).unwrap();
            self.pre_segment_id += 1;
        }

        self.pre_pc = self.state.pc;
        self.pre_image_id = image_id;
        self.pre_hash_root = page_hash_root;
        self.state.load_registers(); // add to rtrace
    }
}

/// se extends the number to 32 bit with sign.
fn sign_extension(dat: u32, idx: u32) -> u32 {
    let is_signed = (dat >> (idx - 1)) != 0;
    let signed = ((1u32 << (32 - idx)) - 1) << idx;
    let mask = (1u32 << idx) - 1;
    if is_signed {
        dat & mask | signed
    } else {
        dat & mask
    }
}
