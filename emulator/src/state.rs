use crate::memory::{Memory, INIT_SP, POSEIDON_RATE_BYTES};
use crate::page::{PAGE_ADDR_MASK, PAGE_SIZE};
use elf::abi::{PT_LOAD, PT_TLS};
use elf::endian::AnyEndian;
use log::{trace, warn};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::fs;
use std::io::{stderr, stdout, Read, Write};
use std::path::Path;

pub const FD_STDIN: u32 = 0;
pub const FD_STDOUT: u32 = 1;
pub const FD_STDERR: u32 = 2;
pub const FD_PUBLIC_VALUES: u32 = 3;
pub const FD_HINT: u32 = 4;
pub const MIPS_EBADF: u32 = 9;

pub const REGISTERS_START: u32 = 0x81020400u32;
pub const PAGE_LOAD_CYCLES: u64 = 128;
pub const PAGE_HASH_CYCLES: u64 = 1;
pub const PAGE_CYCLES: u64 = PAGE_LOAD_CYCLES + PAGE_HASH_CYCLES;
pub const IMAGE_ID_CYCLES: u64 = 3;
pub const MAX_INSTRUCTION_CYCLES: u64 = PAGE_CYCLES * 6; //TOFIX
pub const RESERVE_CYCLES: u64 = IMAGE_ID_CYCLES + MAX_INSTRUCTION_CYCLES;

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
    pub step: u64,
    pub input_stream: Vec<Vec<u8>>,
    pub input_stream_ptr: usize,
    pub public_values_stream: Vec<u8>,
    pub public_values_stream_ptr: usize,
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

    /// brk handles the brk syscall
    brk: u32,

    /// tlb addr
    local_user: u32,

    /// step tracks the total step has been executed.
    pub step: u64,
    pub total_step: u64,

    /// cycle tracks the total cycle has been executed.
    pub cycle: u64,
    pub total_cycle: u64,

    /// A stream of input values (global to the entire program).
    pub input_stream: Vec<Vec<u8>>,

    /// A ptr to the current position in the input stream incremented by HINT_READ opcode.
    pub input_stream_ptr: usize,

    /// A stream of public values from the program (global to entire program).
    pub public_values_stream: Vec<u8>,

    /// A ptr to the current position in the public values stream, incremented when reading from public_values_stream.
    pub public_values_stream_ptr: usize,

    pub exited: bool,
    pub exit_code: u8,
    dump_info: bool,
}

impl Read for State {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.read_public_values_slice(buf);
        Ok(buf.len())
    }
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
            local_user: 0,
            step: 0,
            total_step: 0,
            cycle: 0,
            total_cycle: 0,
            brk: 0,
            input_stream: Vec::new(),
            input_stream_ptr: 0,
            public_values_stream: Vec::new(),
            public_values_stream_ptr: 0,
            exited: false,
            exit_code: 0,
            dump_info: false,
        })
    }

    pub fn load_elf(f: &elf::ElfBytes<AnyEndian>) -> Box<Self> {
        let mut s = Box::new(Self {
            memory: Box::new(Memory::new()),
            registers: Default::default(),

            pc: f.ehdr.e_entry as u32,
            next_pc: f.ehdr.e_entry as u32 + 4,

            hi: 0,
            lo: 0,
            heap: 0x20000000,
            local_user: 0,
            step: 0,
            total_step: 0,
            cycle: 0,
            total_cycle: 0,
            brk: 0,
            input_stream: Vec::new(),
            input_stream_ptr: 0,
            public_values_stream: Vec::new(),
            public_values_stream_ptr: 0,
            exited: false,
            exit_code: 0,
            dump_info: false,
        });

        let mut hiaddr = 0u32;
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
                if segment.p_type == PT_LOAD || segment.p_type == PT_TLS {
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

            let a = (segment.p_vaddr + segment.p_memsz) as u32;
            if a > hiaddr {
                hiaddr = a;
            }

            let r: Box<&[u8]> = Box::new(r.as_slice());
            s.memory
                .set_memory_range(segment.p_vaddr as u32, r)
                .expect("failed to set memory range");
        }
        s.brk = hiaddr - (hiaddr & (PAGE_ADDR_MASK as u32)) + PAGE_SIZE as u32;
        s
    }

    pub fn patch_elf(&mut self, f: &elf::ElfBytes<AnyEndian>) {
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
                    | "runtime.check"
                    | "runtime.checkfds"
                    | "_dl_discover_osversion" => {
                        log::debug!("patch {} at {:X}", name, symbol.st_value);
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
                    _ => {
                        if name.contains("sys_common") && name.contains("thread_info") {
                            log::debug!("patch {}", name);
                            let r: Vec<u8> = vec![0x03, 0xe0, 0x00, 0x08, 0, 0, 0, 0];
                            let r = Box::new(r.as_slice());
                            self.memory
                                .set_memory_range(symbol.st_value as u32, r)
                                .expect("set memory range failed");
                        }
                    }
                },
                Err(e) => {
                    warn!("parse symbol failed, {}", e);
                    continue;
                }
            }
        }
    }

    /// We define the input[0] as the public input, and input[1] as the private input
    pub fn patch_stack(&mut self, input: Vec<&str>) {
        assert!(input.len() <= 2);
        // TODO: check the arg size should less than one page??
        // setup stack pointer
        let sp: u32 = INIT_SP;

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
        for item in input {
            items.insert(index, item);
            index += 1u32;
        }

        log::debug!("count {} items {:?}", index, items);
        // init argc,  argv, aux on stack
        store_mem(sp, index);
        let mut cur_sp = sp + 4 * (index + 1);
        store_mem(cur_sp, 0x00); // argv[n] = 0 (terminating argv)
        cur_sp += 4;
        store_mem(cur_sp, 0x00); // envp[term] = 0 (no env vars)
        cur_sp += 4;

        store_mem(cur_sp, 0x06); // auxv[0] = _AT_PAGESZ = 6 (key)
        store_mem(cur_sp + 4, 0x1000); // auxv[1] = page size of 4 KiB (value)
        cur_sp += 8;

        store_mem(cur_sp, 0x0b); // auxv[0] = AT_UID = 11 (key)
        store_mem(cur_sp + 4, 0x3e8); // auxv[1] = Real uid (value)
        cur_sp += 8;
        store_mem(cur_sp, 0x0c); // auxv[0] = AT_EUID = 12 (key)
        store_mem(cur_sp + 4, 0x3e8); // auxv[1] = Effective uid (value)
        cur_sp += 8;
        store_mem(cur_sp, 0x0d); // auxv[0] = AT_GID = 13 (key)
        store_mem(cur_sp + 4, 0x3e8); // auxv[1] = Real gid (value)
        cur_sp += 8;
        store_mem(cur_sp, 0x0e); // auxv[0] = AT_EGID = 14 (key)
        store_mem(cur_sp + 4, 0x3e8); // auxv[1] = Effective gid (value)
        cur_sp += 8;
        store_mem(cur_sp, 0x10); // auxv[0] = AT_HWCAP = 16 (key)
        store_mem(cur_sp + 4, 0x00); // auxv[1] =  arch dependent hints at CPU capabilities (value)
        cur_sp += 8;
        store_mem(cur_sp, 0x11); // auxv[0] = AT_CLKTCK = 17 (key)
        store_mem(cur_sp + 4, 0x64); // auxv[1] = Frequency of times() (value)
        cur_sp += 8;
        store_mem(cur_sp, 0x17); // auxv[0] = AT_SECURE = 23 (key)
        store_mem(cur_sp + 4, 0x00); // auxv[1] = secure mode boolean (value)
        cur_sp += 8;

        store_mem(cur_sp, 0x19); // auxv[4] = AT_RANDOM = 25 (key)
        store_mem(cur_sp + 4, cur_sp + 12); // auxv[5] = address of 16 bytes containing random value
        cur_sp += 8;
        store_mem(cur_sp, 0); // auxv[term] = 0
        cur_sp += 4;
        store_mem(cur_sp, 0x5f28df1d); // auxv[term] = 0
        store_mem(cur_sp + 4, 0x2cd1002a); // auxv[term] = 0
        store_mem(cur_sp + 8, 0x5ff9f682); // auxv[term] = 0
        store_mem(cur_sp + 12, 0xd4d8d538); // auxv[term] = 0
        cur_sp += 16;
        store_mem(cur_sp, 0x00); // auxv[term] = 0
        cur_sp += 4;

        let mut store_mem_str = |paddr: u32, daddr: u32, str: &str| {
            let mut dat = [0u8; 4];
            dat.copy_from_slice(&daddr.to_be_bytes());
            let r = Box::new(dat.as_slice());
            self.memory
                .set_memory_range(paddr, r)
                .expect("failed to set memory range");
            let r = Box::new(str.as_bytes());
            log::debug!("Write inputs: {} {:?}", daddr, r);
            self.memory
                .set_memory_range(daddr, r)
                .expect("failed to set memory range");
        };

        for (ind, inp) in items.iter() {
            let index = *ind;
            store_mem_str(sp + 4 * (index + 1), cur_sp, inp);
            cur_sp += inp.len() as u32 + 1;
        }
    }

    pub fn add_input_stream<T: Serialize>(&mut self, input: &T) {
        let mut buf = Vec::new();
        bincode::serialize_into(&mut buf, input).expect("serialization failed");
        self.input_stream.push(buf);
    }

    pub fn read_public_values<T: DeserializeOwned>(&mut self) -> T {
        let result = bincode::deserialize_from::<_, T>(self);
        result.unwrap()
    }

    pub fn read_public_values_slice(&mut self, buf: &mut [u8]) {
        let len = buf.len();
        let start = self.public_values_stream_ptr;
        let end = start + len;
        assert!(end <= self.public_values_stream.len());
        buf.copy_from_slice(&self.public_values_stream[start..end]);
        self.public_values_stream_ptr = end;
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

        log::debug!("load preimage {}", data.len());

        let data_len = data.len();
        self.memory.set_memory(0x31000000, data_len as u32);

        self.memory
            .set_memory_range(0x31000004, data)
            .expect("set memory range failed");

        self.cycle += (data_len as u64 + 35) / 32;
        let len = data_len & 3;
        let end = data_len % POSEIDON_RATE_BYTES;

        if len != 0 {
            let mut bytes = [0u8; 4];
            let final_addr = 0x31000004 + data_len - len;
            let word = self.memory.get_memory(final_addr as u32);
            bytes[0..len].copy_from_slice(&word.to_be_bytes()[0..len]);
            bytes[len] = 1;
            if end + 4 > POSEIDON_RATE_BYTES {
                bytes[3] |= 0b10000000;
            }
            self.memory
                .set_memory(final_addr as u32, u32::from_be_bytes(bytes));
        }
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

    pub fn get_registers_bytes(&mut self) -> [u8; 39 * 4] {
        let mut regs_bytes_be = [0u8; 39 * 4];
        for i in 0..32 {
            regs_bytes_be[i * 4..i * 4 + 4].copy_from_slice(&self.registers[i].to_be_bytes());
        }

        regs_bytes_be[32 * 4..32 * 4 + 4].copy_from_slice(&self.lo.to_be_bytes());
        regs_bytes_be[33 * 4..33 * 4 + 4].copy_from_slice(&self.hi.to_be_bytes());
        regs_bytes_be[34 * 4..34 * 4 + 4].copy_from_slice(&self.heap.to_be_bytes());
        regs_bytes_be[35 * 4..35 * 4 + 4].copy_from_slice(&self.pc.to_be_bytes());
        regs_bytes_be[36 * 4..36 * 4 + 4].copy_from_slice(&self.next_pc.to_be_bytes());
        regs_bytes_be[37 * 4..37 * 4 + 4].copy_from_slice(&self.brk.to_be_bytes());
        regs_bytes_be[38 * 4..38 * 4 + 4].copy_from_slice(&self.local_user.to_be_bytes());
        regs_bytes_be
    }
}

pub struct InstrumentedState {
    /// state stores the state of the MIPS emulator
    pub state: Box<State>,

    /// writer for stdout
    stdout_writer: Box<dyn Write>,
    /// writer for stderr
    stderr_writer: Box<dyn Write>,

    pub pre_segment_id: u32,
    pre_pc: u32,
    pre_image_id: [u8; 32],
    pre_hash_root: [u8; 32],
    block_path: String,
    pre_input: Vec<Vec<u8>>,
    pre_input_ptr: usize,
    pre_public_values: Vec<u8>,
    pre_public_values_ptr: usize,
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
            pre_input: Vec::new(),
            pre_input_ptr: 0,
            pre_public_values: Vec::new(),
            pre_public_values_ptr: 0,
        })
    }

    fn handle_syscall(&mut self) {
        let syscall_num = self.state.registers[2]; // v0
        let mut v0 = 0u32;
        let mut v1 = 0u32;

        let a0 = self.state.registers[4];
        let a1 = self.state.registers[5];
        let a2 = self.state.registers[6];

        self.state.dump_info = true;

        log::debug!("syscall {} {} {} {}", syscall_num, a0, a1, a2);

        match syscall_num {
            0xF0 => {
                if self.state.input_stream_ptr >= self.state.input_stream.len() {
                    panic!("not enough vecs in hint input stream");
                }
                log::debug!(
                    "hint len {:X}",
                    self.state.input_stream[self.state.input_stream_ptr].len()
                );
                v0 = self.state.input_stream[self.state.input_stream_ptr].len() as u32
            }
            0xF1 => {
                log::debug!("{:X} {:X} {:X}", a0, a1, a2);
                if self.state.input_stream_ptr >= self.state.input_stream.len() {
                    warn!("not enough vecs in hint input stream");
                }

                let vec: &Vec<u8> = &self.state.input_stream[self.state.input_stream_ptr];
                self.state.input_stream_ptr += 1;
                assert_eq!(
                    vec.len() as u32,
                    a1,
                    "hint input stream read length mismatch"
                );
                log::debug!("input: {:?}", vec);
                assert_eq!(a0 % 4, 0, "hint read address not aligned to 4 bytes");
                if a1 >= 1 {
                    self.state.cycle += (a1 as u64 + 31) / 32;
                }
                for i in (0..a1).step_by(4) {
                    // Get each byte in the chunk
                    let b1 = vec[i as usize];
                    // In case the vec is not a multiple of 4, right-pad with 0s. This is fine because we
                    // are assuming the word is uninitialized, so filling it with 0s makes sense.
                    let b2 = vec.get(i as usize + 1).copied().unwrap_or(0);
                    let b3 = vec.get(i as usize + 2).copied().unwrap_or(0);
                    let b4 = vec.get(i as usize + 3).copied().unwrap_or(0);
                    let word = u32::from_be_bytes([b1, b2, b3, b4]);

                    // Save the data into runtime state so the runtime will use the desired data instead of
                    // 0 when first reading/writing from this address.
                    self.state.memory.set_memory(a0 + i, word);
                }
                v0 = a2
            }
            4020 => {
                // read preimage (getpid)
                self.state.load_preimage(self.block_path.clone())
            }
            4210 | 4090 => {
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
                if a0 > self.state.brk {
                    v0 = a0;
                } else {
                    v0 = self.state.brk;
                }
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
                        v0 = 0xffffffff;
                        v1 = MIPS_EBADF;
                    }
                }
            }
            4004 => {
                // write
                // args: a0 = fd, a1 = addr, a2 = count
                // returns: v0 = written, v1 = err code
                let bytes = (0..a2)
                    .map(|i| self.state.memory.byte(a1 + i))
                    .collect::<Vec<u8>>();
                let slice = bytes.as_slice();
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
                    FD_PUBLIC_VALUES => {
                        self.state.public_values_stream.extend_from_slice(slice);
                        v0 = a2;
                    }
                    FD_HINT => {
                        self.state.input_stream.push(slice.to_vec());
                        v0 = a2;
                    }
                    _ => {
                        v0 = 0xffffffff;
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
                            v0 = 0xffffffff;
                            v1 = MIPS_EBADF;
                        }
                    }
                } else if a1 == 1 {
                    // GET_FD
                    match a0 {
                        FD_STDIN | FD_STDOUT | FD_STDERR => v0 = a0,
                        _ => {
                            v0 = 0xffffffff;
                            v1 = MIPS_EBADF;
                        }
                    }
                } else {
                    v0 = 0xffffffff;
                    v1 = MIPS_EBADF;
                }
            }
            4283 => {
                log::trace!("set local user {:X} {:X} {:X}", a0, a1, a2);
                self.state.local_user = a0;
            }
            0xF2 => {
                log::trace!("sys_verify {:X} {:X} {:X}", a0, a1, a2);
                // DO Nothing Here
            }
            _ => {}
        }

        self.state.registers[2] = v0;
        self.state.registers[7] = v1;

        self.state.pc = self.state.next_pc;
        self.state.next_pc += 4;
    }

    fn handle_branch(&mut self, opcode: u32, insn: u32, rt_reg: u32, rs: u32) {
        self.state.dump_info = true;
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
                } else if rtv == 0b10001 {
                    // bal  000001 00000 10001 offset
                    self.state.registers[31] = self.state.pc + 8;
                    true
                } else {
                    false
                }
            }
            _ => {
                panic!("invalid branch opcode {}", opcode);
            }
        };

        let prev_pc = self.state.pc;
        self.state.pc = self.state.next_pc; // execute the delay slot first
        if should_branch {
            // then continue with the instruction the branch jumps to.
            self.state.next_pc =
                (prev_pc as u64 + 4u64 + (sign_extension(insn & 0xFFFF, 16) << 2) as u64) as u32;
        } else {
            self.state.next_pc += 4;
        }
    }

    fn handle_jump(&mut self, link_reg: u32, dest: u32) {
        let prev_pc = self.state.pc;
        self.state.pc = self.state.next_pc;
        self.state.next_pc = dest;

        if link_reg != 0 {
            // set the link-register to the instr after the delay slot instruction.
            self.state.registers[link_reg as usize] = prev_pc + 8;
        }
        self.state.dump_info = true;
    }

    fn handle_trap(&mut self) {
        // do nothing currently
        self.state.dump_info = true;
    }

    fn handle_hilo(&mut self, fun: u32, rs: u32, rt: u32, store_reg: u32) {
        let mut val = 0u32;
        match fun {
            0x01 => {
                // maddu
                let mut acc = (rs as u64).wrapping_mul(rt as u64);
                let hilo = ((self.state.hi as u64) << 32).wrapping_add(self.state.lo as u64);
                acc = acc.wrapping_add(hilo);
                self.state.hi = (acc >> 32) as u32;
                self.state.lo = acc as u32;
            }
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
        self.state.cycle += 1;

        // fetch instruction
        let insn = self.state.memory.get_memory(self.state.pc);
        let opcode = insn >> 26; // 6-bits

        log::trace!("pc: {:X}, insn: {:X}", self.state.pc, insn);

        // j-type j/jal
        if opcode == 2 || opcode == 3 {
            let link_reg = match opcode {
                3 => 31,
                _ => 0,
            };

            self.handle_jump(link_reg, sign_extension(insn & 0x03ffffff, 26) << 2);
            return;
        }

        // fetch register
        let mut rt = 0u32;
        let rt_reg = (insn >> 16) & 0x1f;

        // R-type or I-type (stores rt)
        let mut rs = self.state.registers[((insn >> 21) & 0x1f) as usize];
        let mut rd_reg = rt_reg;
        let fun = insn & 0x3f;
        if opcode == 0 || opcode == 0x1c || (opcode == 0x1F && (fun == 0x20 || fun == 4)) {
            // R-type (stores rd), partial Special3 insts: ins, seb, seh, wsbh
            rt = self.state.registers[rt_reg as usize];
            rd_reg = (insn >> 11) & 0x1f;
        } else if opcode < 0x20 {
            // rt is SignExtImm
            // don't sign extend for andi, ori, xori
            if opcode == 0xC || opcode == 0xD || opcode == 0xE {
                // ZeroExtImm
                rt = insn & 0xFFFF;
            } else {
                rt = sign_extension(insn & 0xffff, 16);
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

        let mut store_addr: u32 = 0xffffffff;
        // memory fetch (all I-type)
        // we do the load for stores also
        let mut mem: u32 = 0;
        if opcode >= 0x20 {
            // M[R[rs]+SignExtImm]
            rs = (rs as u64 + sign_extension(insn & 0xffff, 16) as u64) as u32;
            let addr = rs & 0xfffffffc;
            mem = self.state.memory.get_memory(addr);
            if opcode >= 0x28 && opcode != 0x30 {
                // store
                store_addr = addr;
                // store opcodes don't write back to a register
                rd_reg = 0;
            }
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

        if opcode == 0x1C && fun == 0x1 {
            // maddu
            self.handle_hilo(fun, rs, rt, rd_reg);
            return;
        }

        if opcode == 0 && fun == 0x34 && val == 1 {
            self.handle_trap();
        }

        // stupid sc, write a 1 to rt
        if opcode == 0x38 && rt_reg != 0 {
            self.state.registers[rt_reg as usize] = 1;
        }

        if opcode == 0x33 {
            //pref
            self.handle_rd(0, val, false);
            return;
        }

        // write memory
        if store_addr != 0xffffffff {
            //let value_prev = self.state.memory.get_memory(store_addr);
            log::trace!("write memory {:X}, {:X}", store_addr, val);
            self.state.memory.set_memory(store_addr, val);
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
                        if (insn >> 21) & 0x1F == 1 {
                            return rt >> shamt | rt << (32 - shamt); // ror
                        } else if (insn >> 21) & 0x1F == 0 {
                            return rt >> shamt; // srl
                        }
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
                    0x34 => {
                        return if rs == rt {
                            1 // teq
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
                if fun == 1 {
                    //maddu: do nothing here
                    return rs;
                }
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
            } else if opcode == 0x1F {
                // SPECIAL3
                if fun == 0 {
                    // ext
                    let msbd = (insn >> 11) & 0x1F;
                    let lsb = (insn >> 6) & 0x1F;
                    let mask = (1 << (msbd + 1)) - 1;
                    let i = (rs >> lsb) & mask;
                    return i;
                } else if fun == 4 {
                    // ins
                    let msb = (insn >> 11) & 0x1F;
                    let lsb = (insn >> 6) & 0x1F;
                    let size = msb - lsb + 1;
                    let mask = (1u32 << size) - 1;
                    return (rt & !(mask << lsb)) | ((rs & mask) << lsb);
                } else if fun == 0b111011 {
                    //rdhwr
                    let rd = (insn >> 11) & 0x1F;
                    if rd == 0 {
                        return 1; // cpu number
                    } else if rd == 29 {
                        log::trace!("pc: {:X} rdhwr {:X}", self.state.pc, self.state.local_user);
                        //return 0x946490;  // a pointer to a thread-specific storage block
                        return self.state.local_user;
                    } else {
                        return 0;
                    }
                } else if fun == 0b100000 {
                    let shamt = (insn >> 6) & 0x1F;
                    if shamt == 0x18 {
                        // seh
                        return sign_extension(rt, 16);
                    } else if shamt == 0x10 {
                        // seb
                        return sign_extension(rt, 8);
                    } else if shamt == 0x02 {
                        // wsbh
                        return (((rt >> 16) & 0xFF) << 24)
                            | (((rt >> 24) & 0xFF) << 16)
                            | ((rt & 0xFF) << 8)
                            | ((rt >> 8) & 0xFF);
                    }
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
                    let mask = 0xffffffffu32 << ((rs & 3) * 8);
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
                    let mask = 0xffffffffu32 >> (24 - (rs & 3) * 8);
                    return (rt & (!mask)) | val;
                }
                _ => {}
            }
        } else if opcode == 0x28 {
            // sb
            let val = (rt & 0xff) << (24 - (rs & 3) * 8);
            let mask = 0xffffffffu32 ^ (0xff << (24 - (rs & 3) * 8));
            return (mem & mask) | val;
        } else if opcode == 0x29 {
            // sh
            let val = (rt & 0xffff) << (16 - (rs & 2) * 8);
            let mask = 0xffffffffu32 ^ (0xffff << (16 - (rs & 2) * 8));
            return (mem & mask) | val;
        } else if opcode == 0x2a {
            // swl
            let val = rt >> ((rs & 3) * 8);
            let mask = 0xffffffffu32 >> ((rs & 3) * 8);
            return (mem & (!mask)) | val;
        } else if opcode == 0x2b {
            // sw
            return rt;
        } else if opcode == 0x2e {
            // swr
            let val = rt << (24 - (rs & 3) * 8);
            let mask = 0xffffffffu32 << (24 - (rs & 3) * 8);
            return (mem & (!mask)) | val;
        } else if opcode == 0x30 {
            // ll
            return mem;
        } else if opcode == 0x33 {
            // pref
            return mem;
        } else if opcode == 0x38 {
            // sc
            return rt;
        } else if opcode == 0x3D {
            // sdc1
            return 0;
        }

        panic!(
            "invalid instruction, opcode: {:X} {:X} {:X}",
            opcode, insn, self.state.pc
        );
    }

    pub fn step(&mut self) -> u64 {
        let dump: bool = self.state.dump_info;
        self.state.dump_info = false;

        self.mips_step();
        if dump {
            log::trace!(
                "pc: {:X} regs: {:X?}\n",
                self.state.pc,
                self.state.registers
            );
        };

        self.state.cycle + (self.state.memory.page_count() + 1) * PAGE_CYCLES + RESERVE_CYCLES
    }

    /// the caller should provide a write to write segemnt if proof is true
    pub fn split_segment<W: Write>(
        &mut self,
        proof: bool,
        output: &str,
        new_writer: fn(&str) -> Option<W>,
    ) {
        self.state.total_cycle +=
            self.state.cycle + (self.state.memory.page_count() + 1) * PAGE_CYCLES;
        self.state.total_step += self.state.step;
        self.state.memory.update_page_hash();
        let regiters = self.state.get_registers_bytes();

        // load public input, assume the max size of public input is 6KB.
        let _ = self.state.memory.get_memory(INIT_SP);
        let _ = self.state.memory.get_memory(INIT_SP + PAGE_SIZE as u32);

        let (image_id, page_hash_root) =
            self.state.memory.compute_image_id(self.state.pc, &regiters);
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
                step: self.state.step,
                page_hash_root,
                input_stream: self.pre_input.clone(),
                input_stream_ptr: self.pre_input_ptr,
                public_values_stream: self.pre_public_values.clone(),
                public_values_stream_ptr: self.pre_public_values_ptr,
            };
            let name = format!("{output}/{}", self.pre_segment_id);
            log::debug!("split: file {}", name);
            let mut f = new_writer(&name).unwrap();
            let data = serde_json::to_vec(&segment).unwrap();
            f.write_all(data.as_slice()).unwrap();
            self.pre_segment_id += 1;
        }

        self.pre_input = self.state.input_stream.clone();
        self.pre_input_ptr = self.state.input_stream_ptr;
        self.pre_public_values = self.state.public_values_stream.clone();
        self.pre_public_values_ptr = self.state.public_values_stream_ptr;
        self.pre_pc = self.state.pc;
        self.pre_image_id = image_id;
        self.pre_hash_root = page_hash_root;
        self.state.cycle = 0;
        self.state.step = 0;
    }

    pub fn dump_memory(&mut self) {
        let image = self.state.memory.get_total_image();
        for (addr, val) in image.iter() {
            log::trace!("{:X}: {:X}", addr, val);
        }
    }
}

/// se extends the number to 32 bit with sign.
fn sign_extension(dat: u32, idx: u32) -> u32 {
    let is_signed = ((dat >> (idx - 1)) & 1) != 0;
    let signed = ((1u32 << (32 - idx)) - 1) << idx;
    let mask = (1u32 << idx) - 1;
    if is_signed {
        dat & mask | signed
    } else {
        dat & mask
    }
}
