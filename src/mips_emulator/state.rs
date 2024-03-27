use crate::cpu::kernel::elf::INIT_SP;
use crate::mips_emulator::memory::Memory;
use crate::mips_emulator::page::{PAGE_ADDR_MASK, PAGE_SIZE};
use crate::mips_emulator::witness::{Program, ProgramSegment};
use crate::poseidon_sponge::columns::POSEIDON_RATE_BYTES;
use elf::abi::{PT_LOAD, PT_TLS};
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

pub const SEGMENT_STEPS: usize = 1024;
pub const REGISTERS_START: u32 = 0x81020400u32;

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
    pub exit_code: u8,
    dump_info: bool,
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
            dump_info: false,
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
            dump_info: false,
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
                    | "runtime.check"
                    | "__libc_setup_tls"
                    | "__libc_pthread_init"
                    | "_dl_discover_osversion"
                    | "_dl_non_dynamic_init"
                    | "_ZN3std9panicking3try7do_call17hed6da35bd3622d54E"
                    => {
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
    /*
        let mut items: BTreeMap<u32, &str> = BTreeMap::new();
        let mut index = 0;
        for item in input {
            items.insert(index, item);
            index += 1u32;
        }

        log::debug!("count {} items {:?}", index, items);
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
            log::debug!("Write inputs: {} {:?}", daddr, r);
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
    */
        let data = [
/* 0x7fFFc900*/   0x00000001, 0x7fFFcb14, 0x00000000, 0x7fFFcb27
/* 0x7fFFc910*/ , 0x7fFFcb43, 0x7fFFcb6f, 0x7fFFcb86, 0x7fFFcbbc
/* 0x7fFFc920*/ , 0x7fFFcbe4, 0x7fFFcbf6, 0x7fFFceb3, 0x7fFFced5
/* 0x7fFFc930*/ , 0x7fFFcf2a, 0x7fFFcf41, 0x7fFFcf8b, 0x7fFFcf9f
/* 0x7fFFc940*/ , 0x7fFFcfc1, 0x7fFFcfe0, 0x7ffff002, 0x7ffff00f
/* 0x7fFFc950*/ , 0x7ffff02a, 0x7ffff03d, 0x7ffff05f, 0x7ffff082
/* 0x7fFFc960*/ , 0x7ffff09b, 0x7ffff0a3, 0x7ffff0ae, 0x7ffff0cc
/* 0x7fFFc970*/ , 0x7ffff0ef, 0x7ffff0f9, 0x7ffff119, 0x7ffff14c
/* 0x7fFFc980*/ , 0x7ffff184, 0x7ffff1a2, 0x7ffff1b6, 0x7ffff1f5
/* 0x7fFFc990*/ , 0x7ffff20c, 0x7ffff22e, 0x7ffff2ba, 0x7ffff2e6
/* 0x7fFFc9a0*/ , 0x7ffff2fe, 0x7ffff316, 0x7ffff32b, 0x7ffff33b
/* 0x7fFFc9b0*/ , 0x7ffff36a, 0x7ffff38d, 0x7ffff3e3, 0x7ffff3f4
/* 0x7fFFc9c0*/ , 0x7ffff415, 0x7ffff9f7, 0x7ffffa08, 0x7ffffa1d
/* 0x7fFFc9d0*/ , 0x7ffffa2f, 0x7ffffa3d, 0x7ffffa4d, 0x7ffffa5a
/* 0x7fFFc9e0*/ , 0x7ffffa7b, 0x7ffffaa7, 0x7ffffad0, 0x7ffffb05
/* 0x7fFFc9f0*/ , 0x7ffffb39, 0x7ffffb5f, 0x7ffffb74, 0x7ffffb81
/* 0x7fFFca00*/ , 0x7ffffb9c, 0x7ffffbd3, 0x7ffffbef, 0x7ffffc02
/* 0x7fFFca10*/ , 0x7ffffc1a, 0x7ffffc31, 0x7ffffc46, 0x7ffffc6f
/* 0x7fFFca20*/ , 0x7ffffc83, 0x7ffffca3, 0x7ffffcba, 0x7ffffccf
/* 0x7fFFca30*/ , 0x7ffffd05, 0x7ffffd19, 0x7ffffd64, 0x7ffffdb9
/* 0x7fFFca40*/ , 0x7ffffdf1, 0x7ffffe05, 0x7ffffe31, 0x7ffffe54
/* 0x7fFFca50*/ , 0x7ffffe6b, 0x7ffffe81, 0x7ffffeae, 0x7ffffec2
/* 0x7fFFca60*/ , 0x7ffffefc, 0x7fffff0f, 0x7fffff87, 0x7fffffd5
/* 0x7fFFca70*/ , 0x00000000, 0x00000003, 0x00400034, 0x00000004
/* 0x7fFFca80*/ , 0x00000020, 0x00000005, 0x00000007, 0x00000006
/* 0x7fFFca90*/ , 0x00001000, 0x00000007, 0x00000000, 0x00000008
/* 0x7fFFcaa0*/ , 0x00000000, 0x00000009, 0x00400590, 0x0000000b
/* 0x7fFFcab0*/ , 0x000003e8, 0x0000000c, 0x000003e8, 0x0000000d
/* 0x7fFFcac0*/ , 0x000003e8, 0x0000000e, 0x000003e8, 0x00000010
/* 0x7fFFcad0*/ , 0x00000000, 0x00000011, 0x00000064, 0x00000019
/* 0x7fFFcae0*/ , 0x7fFFcb00, 0x00000017, 0x00000000, 0x00000000
/* 0x7fFFcaf0*/ , 0x00000000, 0x00000000, 0x00000000, 0x00000000
/* 0x7fFFcb00*/ , 0x5f28df1d, 0x2cd1002a, 0x5ff9f682, 0xd4d8d538
/* 0x7fFFcb10*/ , 0x00000000, 0x2e2f7465, 0x73742d76, 0x6563746f
/* 0x7fFFcb20*/ , 0x72732f61, 0x6263005f, 0x3d2f7573, 0x722f6269
/* 0x7fFFcb30*/ , 0x6e2f7165, 0x6d752d6d, 0x6970732d, 0x73746174
/* 0x7fFFcb40*/ , 0x6963004f, 0x4c445057, 0x443d2f6d, 0x65646961
/* 0x7fFFcb50*/ , 0x2f6c6977, 0x772f7769, 0x6e646f77, 0x732f776f
/* 0x7fFFcb60*/ , 0x726b7370, 0x6163652f, 0x7a6b6d69, 0x7073004c
/* 0x7fFFcb70*/ , 0x435f4e55, 0x4d455249, 0x433d7a68, 0x5f434e2e
/* 0x7fFFcb80*/ , 0x5554462d, 0x38004442, 0x55535f53, 0x45535349
/* 0x7fFFcb90*/ , 0x4f4e5f42, 0x55535f41, 0x44445245, 0x53533d75
/* 0x7fFFcba0*/ , 0x6e69783a, 0x70617468, 0x3d2f7275, 0x6e2f7573
/* 0x7fFFcbb0*/ , 0x65722f31, 0x3030302f, 0x62757300, 0x464f5243
/* 0x7fFFcbc0*/ , 0x455f5059, 0x54484f4e, 0x5f494e43, 0x3d2f7573
/* 0x7fFFcbd0*/ , 0x722f696e, 0x636c7564, 0x652f7079, 0x74686f6e
/* 0x7fFFcbe0*/ , 0x332e3800, 0x47444d53, 0x45535349, 0x4f4e3d75
/* 0x7fFFcbf0*/ , 0x62756e74, 0x75005041, 0x54483d2f, 0x6d656469
/* 0x7fFFcc00*/ , 0x612f6c69, 0x77772f77, 0x696e646f, 0x77732f77
/* 0x7fFFcc10*/ , 0x6f726b73, 0x70616365, 0x2f73696d, 0x756c6174
/* 0x7fFFcc20*/ , 0x6f722f70, 0x6c63742d, 0x7370696b, 0x652d7a63
/* 0x7fFFcc30*/ , 0x652f6275, 0x696c643a, 0x2f686f6d, 0x652f6c69
/* 0x7fFFcc40*/ , 0x77772f44, 0x6f776e6c, 0x6f616473, 0x2f776176
/* 0x7fFFcc50*/ , 0x6564726f, 0x6d2d6564, 0x69746f72, 0x2d76322e
/* 0x7fFFcc60*/ , 0x392e312d, 0x6c696e75, 0x782d7836, 0x342f3a2f
/* 0x7fFFcc70*/ , 0x686f6d65, 0x2f6c6977, 0x772f2e6f, 0x70616d2f
/* 0x7fFFcc80*/ , 0x64656661, 0x756c742f, 0x62696e2f, 0x3a2f6d65
/* 0x7fFFcc90*/ , 0x6469612f, 0x6c697777, 0x2f77696e, 0x646f7773
/* 0x7fFFcca0*/ , 0x2f776f72, 0x6b737061, 0x63652f73, 0x696d756c
/* 0x7fFFccb0*/ , 0x61746f72, 0x2f736169, 0x6c2d7269, 0x7363762f
/* 0x7fFFccc0*/ , 0x635f656d, 0x756c6174, 0x6f723a2f, 0x6d656469
/* 0x7fFFccd0*/ , 0x612f6c69, 0x77772f77, 0x696e646f, 0x77732f77
/* 0x7fFFcce0*/ , 0x6f726b73, 0x70616365, 0x2f6d696c, 0x6b762f64
/* 0x7fFFccf0*/ , 0x756f2d62, 0x75696c64, 0x726f6f74, 0x2d73646b
/* 0x7fFFcd00*/ , 0x2f686f73, 0x742d746f, 0x6f6c732f, 0x6763632f
/* 0x7fFFcd10*/ , 0x72697363, 0x7636342d, 0x6c696e75, 0x782d6d75
/* 0x7fFFcd20*/ , 0x736c2d78, 0x38365f36, 0x342f6269, 0x6e3a2f6d
/* 0x7fFFcd30*/ , 0x65646961, 0x2f6c6977, 0x772f7769, 0x6e646f77
/* 0x7fFFcd40*/ , 0x732f776f, 0x726b7370, 0x6163652f, 0x746f6f6c
/* 0x7fFFcd50*/ , 0x63686169, 0x6e2f6269, 0x6e2f3a2f, 0x6f70742f
/* 0x7fFFcd60*/ , 0x72697363, 0x762f6269, 0x6e3a2f6d, 0x65646961
/* 0x7fFFcd70*/ , 0x2f6c6977, 0x772f7769, 0x6e646f77, 0x732f776f
/* 0x7fFFcd80*/ , 0x726b7370, 0x6163652f, 0x7a6b6d69, 0x70732f5a
/* 0x7fFFcd90*/ , 0x6f4b7261, 0x7465732f, 0x74617267, 0x65742f72
/* 0x7fFFcda0*/ , 0x656c6561, 0x73653a2f, 0x6d656469, 0x612f6c69
/* 0x7fFFcdb0*/ , 0x77772f77, 0x696e646f, 0x77732f77, 0x6f726b73
/* 0x7fFFcdc0*/ , 0x70616365, 0x2f7a6b6d, 0x6970732f, 0x706c6f6e
/* 0x7fFFcdd0*/ , 0x6b69742f, 0x74617267, 0x65742f72, 0x656c6561
/* 0x7fFFcde0*/ , 0x73653a2f, 0x686f6d65, 0x2f6c6977, 0x772f2e63
/* 0x7fFFcdf0*/ , 0x6172676f, 0x2f62696e, 0x3a2f686f, 0x6d652f6c
/* 0x7fFFce00*/ , 0x6977772f, 0x2e6f7061, 0x6d2f6465, 0x6661756c
/* 0x7fFFce10*/ , 0x742f6269, 0x6e3a2f68, 0x6f6d652f, 0x6c697777
/* 0x7fFFce20*/ , 0x2f2e6c6f, 0x63616c2f, 0x62696e3a, 0x2f757372
/* 0x7fFFce30*/ , 0x2f6c6f63, 0x616c2f73, 0x62696e3a, 0x2f757372
/* 0x7fFFce40*/ , 0x2f6c6f63, 0x616c2f62, 0x696e3a2f, 0x7573722f
/* 0x7fFFce50*/ , 0x7362696e, 0x3a2f7573, 0x722f6269, 0x6e3a2f73
/* 0x7fFFce60*/ , 0x62696e3a, 0x2f62696e, 0x3a2f7573, 0x722f6761
/* 0x7fFFce70*/ , 0x6d65733a, 0x2f757372, 0x2f6c6f63, 0x616c2f67
/* 0x7fFFce80*/ , 0x616d6573, 0x3a2f736e, 0x61702f62, 0x696e3a2f
/* 0x7fFFce90*/ , 0x7573722f, 0x6c6f6361, 0x6c2f676f, 0x2f62696e
/* 0x7fFFcea0*/ , 0x3a2f7573, 0x722f7067, 0x61646d69, 0x6e342f62
/* 0x7fFFceb0*/ , 0x696e0061, 0x6c6c5f70, 0x726f7879, 0x3d736f63
/* 0x7fFFcec0 */, 0x6b733a2f, 0x2f313237, 0x2e302e30, 0x2e313a37
/* 0x7fFFced0 */, 0x3839302f, 0x00584447, 0x5f444154, 0x415f4449
/* 0x7fFFcee0 */, 0x52533d2f, 0x7573722f, 0x73686172, 0x652f7562
/* 0x7fFFcef0 */, 0x756e7475, 0x3a2f7573, 0x722f6c6f, 0x63616c2f
/* 0x7fFFcf00 */, 0x73686172, 0x652f3a2f, 0x7573722f, 0x73686172
/* 0x7fFFcf10 */, 0x652f3a2f, 0x7661722f, 0x6c69622f, 0x736e6170
/* 0x7fFFcf20 */, 0x642f6465, 0x736b746f, 0x70004a4f, 0x55524e41
/* 0x7fFFcf30 */, 0x4c5f5354, 0x5245414d, 0x3d383a35, 0x32303139
/* 0x7fFFcf40 */, 0x00424153, 0x45444952, 0x3d2f6d65, 0x6469612f
/* 0x7fFFcf50 */, 0x6c697777, 0x2f77696e, 0x646f7773, 0x2f776f72
/* 0x7fFFcf60 */, 0x6b737061, 0x63652f7a, 0x6b6d6970, 0x732f6361
/* 0x7fFFcf70 */, 0x6e6e6f6e, 0x2d6d6970, 0x732f626c, 0x6f636b2f
/* 0x7fFFcf80 */, 0x746d702f, 0x63616e6e, 0x6f6e004c, 0x435f5449
/* 0x7fFFcf90 */, 0x4d453d7a, 0x685f434e, 0x2e555446, 0x2d380041
/* 0x7fFFcfa0 */, 0x4c4c5f50, 0x524f5859, 0x3d736f63, 0x6b733a2f
/* 0x7fFFcfb0 */, 0x2f313237, 0x2e302e30, 0x2e313a37, 0x3839302f
/* 0x7fFFcfc0 */, 0x00584447, 0x5f52554e, 0x54494d45, 0x5f444952
/* 0x7fFFcfd0 */, 0x3d2f7275, 0x6e2f7573, 0x65722f31, 0x30303000
/* 0x7fFFcfe0 */, 0x68747470, 0x5f70726f, 0x78793d68, 0x7474703a
/* 0x7fFFcff0 */, 0x2f2f3132, 0x372e302e, 0x302e313a, 0x37383930
/* 0x7ffff000 */, 0x2f005041, 0x50455253, 0x495a453d, 0x6134004c
/* 0x7ffff010 */, 0x435f4d45, 0x41535552, 0x454d454e, 0x543d7a68
/* 0x7ffff020 */, 0x5f434e2e, 0x5554462d, 0x38005154, 0x5f494d5f
/* 0x7ffff030 */, 0x4d4f4455, 0x4c453d66, 0x63697478, 0x00485454
/* 0x7ffff040 */, 0x505f5052, 0x4f58593d, 0x68747470, 0x3a2f2f31
/* 0x7ffff050 */, 0x32372e30, 0x2e302e31, 0x3a373839, 0x302f0048
/* 0x7ffff060 */, 0x54545053, 0x5f50524f, 0x58593d68, 0x7474703a
/* 0x7ffff070 */, 0x2f2f3132, 0x372e302e, 0x302e313a, 0x37383930
/* 0x7ffff080 */, 0x2f004c43, 0x5f54454c, 0x4550484f, 0x4e453d7a
/* 0x7ffff090 */, 0x685f434e, 0x2e555446, 0x2d380053, 0x484c564c
/* 0x7ffff0a0 */, 0x3d310044, 0x4953504c, 0x41593d3a, 0x3000474e
/* 0x7ffff0b0 */, 0x4f4d455f, 0x5445524d, 0x494e414c, 0x5f534552
/* 0x7ffff0c0 */, 0x56494345, 0x3d3a312e, 0x33373900, 0x4e4f5f50
/* 0x7ffff0d0 */, 0x524f5859, 0x3d6c6f63, 0x616c686f, 0x73742c31
/* 0x7ffff0e0 */, 0x32372e30, 0x2e302e30, 0x2f382c3a, 0x3a310055
/* 0x7ffff0f0 */, 0x5345523d, 0x6c697777, 0x004c4553, 0x534f5045
/* 0x7ffff100 */, 0x4e3d7c20, 0x2f757372, 0x2f62696e, 0x2f6c6573
/* 0x7ffff110 */, 0x73706970, 0x65202573, 0x00444546, 0x41554c54
/* 0x7ffff120 */, 0x535f5041, 0x54483d2f, 0x7573722f, 0x73686172
/* 0x7ffff130 */, 0x652f6763, 0x6f6e662f, 0x7562756e, 0x74752e64
/* 0x7ffff140 */, 0x65666175, 0x6c742e70, 0x61746800, 0x54564d5f
/* 0x7ffff150 */, 0x4c4f475f, 0x44454255, 0x473d6972, 0x2f747261
/* 0x7ffff160 */, 0x6e73666f, 0x726d2e63, 0x633d313b, 0x72656c61
/* 0x7ffff170 */, 0x792f6972, 0x2f747261, 0x6e73666f, 0x726d2e63
/* 0x7ffff180 */, 0x633d3100, 0x4c435f49, 0x44454e54, 0x49464943
/* 0x7ffff190 */, 0x4154494f, 0x4e3d7a68, 0x5f434e2e, 0x5554462d
/* 0x7ffff1a0 */, 0x38005445, 0x524d3d78, 0x7465726d, 0x2d323536
/* 0x7ffff1b0 */, 0x636f6c6f, 0x72005059, 0x54484f4e, 0x50415448
/* 0x7ffff1c0 */, 0x3d2f6d65, 0x6469612f, 0x6c697777, 0x2f77696e
/* 0x7ffff1d0 */, 0x646f7773, 0x2f776f72, 0x6b737061, 0x63652f73
/* 0x7ffff1e0 */, 0x696d756c, 0x61746f72, 0x2f74766d, 0x2f707974
/* 0x7ffff1f0 */, 0x686f6e3a, 0x00584447, 0x5f534553, 0x53494f4e
/* 0x7ffff200 */, 0x5f434c41, 0x53533d75, 0x73657200, 0x4c455353
/* 0x7ffff210 */, 0x434c4f53, 0x453d2f75, 0x73722f62, 0x696e2f6c
/* 0x7ffff220 */, 0x65737370, 0x69706520, 0x25732025, 0x73005254
/* 0x7ffff230 */, 0x545f4558, 0x45435f50, 0x4154483d, 0x2f686f6d
/* 0x7ffff240 */, 0x652f6c69, 0x77772f44, 0x6f776e6c, 0x6f616473
/* 0x7ffff250 */, 0x2f726973, 0x63763634, 0x2d6c696e, 0x75782d6d
/* 0x7ffff260 */, 0x75736c65, 0x6162695f, 0x666f725f, 0x7838365f
/* 0x7ffff270 */, 0x36342d70, 0x632d6c69, 0x6e75782d, 0x676e755f
/* 0x7ffff280 */, 0x6c617465, 0x73742f72, 0x69736376, 0x36342d6c
/* 0x7ffff290 */, 0x696e7578, 0x2d6d7573, 0x6c656162, 0x695f666f
/* 0x7ffff2a0 */, 0x725f7838, 0x365f3634, 0x2d70632d, 0x6c696e75
/* 0x7ffff2b0 */, 0x782d676e, 0x752f6269, 0x6e00464f, 0x5243455f
/* 0x7ffff2c0 */, 0x50595448, 0x4f4e5f4c, 0x49423d2f, 0x7573722f
/* 0x7ffff2d0 */, 0x6c69622f, 0x7838365f, 0x36342d6c, 0x696e7578
/* 0x7ffff2e0 */, 0x2d676e75, 0x2f00474a, 0x535f4445, 0x4255475f
/* 0x7ffff2f0 */, 0x4f555450, 0x55543d73, 0x74646572, 0x7200434c
/* 0x7ffff300 */, 0x55545445, 0x525f494d, 0x5f4d4f44, 0x554c453d
/* 0x7ffff310 */, 0x66636974, 0x7800474f, 0x524f4f54, 0x3d2f7573
/* 0x7ffff320 */, 0x722f6c6f, 0x63616c2f, 0x676f004d, 0x414e4147
/* 0x7ffff330 */, 0x45525049, 0x443d3139, 0x31320049, 0x4e564f43
/* 0x7ffff340 */, 0x4154494f, 0x4e5f4944, 0x3d363737, 0x65366662
/* 0x7ffff350 */, 0x36333534, 0x34346431, 0x63613762, 0x38366537
/* 0x7ffff360 */, 0x31396538, 0x65353164, 0x65006874, 0x7470735f
/* 0x7ffff370 */, 0x70726f78, 0x793d6874, 0x74703a2f, 0x2f313237
/* 0x7ffff380 */, 0x2e302e30, 0x2e313a37, 0x3839302f, 0x00474e4f
/* 0x7ffff390 */, 0x4d455f54, 0x45524d49, 0x4e414c5f, 0x53435245
/* 0x7ffff3a0 */, 0x454e3d2f, 0x6f72672f, 0x676e6f6d, 0x652f5465
/* 0x7ffff3b0 */, 0x726d696e, 0x616c2f73, 0x63726565, 0x6e2f3532
/* 0x7ffff3c0 */, 0x64643731, 0x38655f35, 0x3163325f, 0x34346561
/* 0x7ffff3d0 */, 0x5f623661, 0x625f6266, 0x36663466, 0x62353766
/* 0x7ffff3e0 */, 0x32660056, 0x54455f56, 0x45525349, 0x4f4e3d36
/* 0x7ffff3f0 */, 0x30303300, 0x5844475f, 0x43555252, 0x454e545f
/* 0x7ffff400 */, 0x4445534b, 0x544f503d, 0x7562756e, 0x74753a47
/* 0x7ffff410 */, 0x4e4f4d45, 0x004c535f, 0x434f4c4f, 0x52533d72
/* 0x7ffff420 */, 0x733d303a, 0x64693d30, 0x313b3334, 0x3a6c6e3d
/* 0x7ffff430 */, 0x30313b33, 0x363a6d68, 0x3d30303a, 0x70693d34
/* 0x7ffff440 */, 0x303b3333, 0x3a736f3d, 0x30313b33, 0x353a646f
/* 0x7ffff450 */, 0x3d30313b, 0x33353a62, 0x643d3430, 0x3b33333b
/* 0x7ffff460 */, 0x30313a63, 0x643d3430, 0x3b33333b, 0x30313a6f
/* 0x7ffff470 */, 0x723d3430, 0x3b33313b, 0x30313a6d, 0x693d3030
/* 0x7ffff480 */, 0x3a73753d, 0x33373b34, 0x313a7367, 0x3d33303b
/* 0x7ffff490 */, 0x34333a63, 0x613d3330, 0x3b34313a, 0x74773d33
/* 0x7ffff4a0 */, 0x303b3432, 0x3a6f773d, 0x33343b34, 0x323a7374
/* 0x7ffff4b0 */, 0x3d33373b, 0x34343a65, 0x783d3031, 0x3b33323a
/* 0x7ffff4c0 */, 0x2a2e7461, 0x723d3031, 0x3b33313a, 0x2a2e7467
/* 0x7ffff4d0 */, 0x7a3d3031, 0x3b33313a, 0x2a2e6172, 0x633d3031
/* 0x7ffff4e0 */, 0x3b33313a, 0x2a2e6172, 0x6a3d3031, 0x3b33313a
/* 0x7ffff4f0 */, 0x2a2e7461, 0x7a3d3031, 0x3b33313a, 0x2a2e6c68
/* 0x7ffff500 */, 0x613d3031, 0x3b33313a, 0x2a2e6c7a, 0x343d3031
/* 0x7ffff510 */, 0x3b33313a, 0x2a2e6c7a, 0x683d3031, 0x3b33313a
/* 0x7ffff520 */, 0x2a2e6c7a, 0x6d613d30, 0x313b3331, 0x3a2a2e74
/* 0x7ffff530 */, 0x6c7a3d30, 0x313b3331, 0x3a2a2e74, 0x787a3d30
/* 0x7ffff540 */, 0x313b3331, 0x3a2a2e74, 0x7a6f3d30, 0x313b3331
/* 0x7ffff550 */, 0x3a2a2e74, 0x377a3d30, 0x313b3331, 0x3a2a2e7a
/* 0x7ffff560 */, 0x69703d30, 0x313b3331, 0x3a2a2e7a, 0x3d30313b
/* 0x7ffff570 */, 0x33313a2a, 0x2e647a3d, 0x30313b33, 0x313a2a2e
/* 0x7ffff580 */, 0x677a3d30, 0x313b3331, 0x3a2a2e6c, 0x727a3d30
/* 0x7ffff590 */, 0x313b3331, 0x3a2a2e6c, 0x7a3d3031, 0x3b33313a
/* 0x7ffff5a0 */, 0x2a2e6c7a, 0x6f3d3031, 0x3b33313a, 0x2a2e787a
/* 0x7ffff5b0 */, 0x3d30313b, 0x33313a2a, 0x2e7a7374, 0x3d30313b
/* 0x7ffff5c0 */, 0x33313a2a, 0x2e747a73, 0x743d3031, 0x3b33313a
/* 0x7ffff5d0 */, 0x2a2e627a, 0x323d3031, 0x3b33313a, 0x2a2e627a
/* 0x7ffff5e0 */, 0x3d30313b, 0x33313a2a, 0x2e74627a, 0x3d30313b
/* 0x7ffff5f0 */, 0x33313a2a, 0x2e74627a, 0x323d3031, 0x3b33313a
/* 0x7ffff600 */, 0x2a2e747a, 0x3d30313b, 0x33313a2a, 0x2e646562
/* 0x7ffff610 */, 0x3d30313b, 0x33313a2a, 0x2e72706d, 0x3d30313b
/* 0x7ffff620 */, 0x33313a2a, 0x2e6a6172, 0x3d30313b, 0x33313a2a
/* 0x7ffff630 */, 0x2e776172, 0x3d30313b, 0x33313a2a, 0x2e656172
/* 0x7ffff640 */, 0x3d30313b, 0x33313a2a, 0x2e736172, 0x3d30313b
/* 0x7ffff650 */, 0x33313a2a, 0x2e726172, 0x3d30313b, 0x33313a2a
/* 0x7ffff660 */, 0x2e616c7a, 0x3d30313b, 0x33313a2a, 0x2e616365
/* 0x7ffff670 */, 0x3d30313b, 0x33313a2a, 0x2e7a6f6f, 0x3d30313b
/* 0x7ffff680 */, 0x33313a2a, 0x2e637069, 0x6f3d3031, 0x3b33313a
/* 0x7ffff690 */, 0x2a2e377a, 0x3d30313b, 0x33313a2a, 0x2e727a3d
/* 0x7ffff6a0 */, 0x30313b33, 0x313a2a2e, 0x6361623d, 0x30313b33
/* 0x7ffff6b0 */, 0x313a2a2e, 0x77696d3d, 0x30313b33, 0x313a2a2e
/* 0x7ffff6c0 */, 0x73776d3d, 0x30313b33, 0x313a2a2e, 0x64776d3d
/* 0x7ffff6d0 */, 0x30313b33, 0x313a2a2e, 0x6573643d, 0x30313b33
/* 0x7ffff6e0 */, 0x313a2a2e, 0x6a70673d, 0x30313b33, 0x353a2a2e
/* 0x7ffff6f0 */, 0x6a706567, 0x3d30313b, 0x33353a2a, 0x2e6d6a70
/* 0x7ffff700 */, 0x673d3031, 0x3b33353a, 0x2a2e6d6a, 0x7065673d
/* 0x7ffff710 */, 0x30313b33, 0x353a2a2e, 0x6769663d, 0x30313b33
/* 0x7ffff720 */, 0x353a2a2e, 0x626d703d, 0x30313b33, 0x353a2a2e
/* 0x7ffff730 */, 0x70626d3d, 0x30313b33, 0x353a2a2e, 0x70676d3d
/* 0x7ffff740 */, 0x30313b33, 0x353a2a2e, 0x70706d3d, 0x30313b33
/* 0x7ffff750 */, 0x353a2a2e, 0x7467613d, 0x30313b33, 0x353a2a2e
/* 0x7ffff760 */, 0x78626d3d, 0x30313b33, 0x353a2a2e, 0x78706d3d
/* 0x7ffff770 */, 0x30313b33, 0x353a2a2e, 0x7469663d, 0x30313b33
/* 0x7ffff780 */, 0x353a2a2e, 0x74696666, 0x3d30313b, 0x33353a2a
/* 0x7ffff790 */, 0x2e706e67, 0x3d30313b, 0x33353a2a, 0x2e737667
/* 0x7ffff7a0 */, 0x3d30313b, 0x33353a2a, 0x2e737667, 0x7a3d3031
/* 0x7ffff7b0 */, 0x3b33353a, 0x2a2e6d6e, 0x673d3031, 0x3b33353a
/* 0x7ffff7c0 */, 0x2a2e7063, 0x783d3031, 0x3b33353a, 0x2a2e6d6f
/* 0x7ffff7d0 */, 0x763d3031, 0x3b33353a, 0x2a2e6d70, 0x673d3031
/* 0x7ffff7e0 */, 0x3b33353a, 0x2a2e6d70, 0x65673d30, 0x313b3335
/* 0x7ffff7f0 */, 0x3a2a2e6d, 0x32763d30, 0x313b3335, 0x3a2a2e6d
/* 0x7ffff800 */, 0x6b763d30, 0x313b3335, 0x3a2a2e77, 0x65626d3d
/* 0x7ffff810 */, 0x30313b33, 0x353a2a2e, 0x6f676d3d, 0x30313b33
/* 0x7ffff820 */, 0x353a2a2e, 0x6d70343d, 0x30313b33, 0x353a2a2e
/* 0x7ffff830 */, 0x6d34763d, 0x30313b33, 0x353a2a2e, 0x6d703476
/* 0x7ffff840 */, 0x3d30313b, 0x33353a2a, 0x2e766f62, 0x3d30313b
/* 0x7ffff850 */, 0x33353a2a, 0x2e71743d, 0x30313b33, 0x353a2a2e
/* 0x7ffff860 */, 0x6e75763d, 0x30313b33, 0x353a2a2e, 0x776d763d
/* 0x7ffff870 */, 0x30313b33, 0x353a2a2e, 0x6173663d, 0x30313b33
/* 0x7ffff880 */, 0x353a2a2e, 0x726d3d30, 0x313b3335, 0x3a2a2e72
/* 0x7ffff890 */, 0x6d76623d, 0x30313b33, 0x353a2a2e, 0x666c633d
/* 0x7ffff8a0 */, 0x30313b33, 0x353a2a2e, 0x6176693d, 0x30313b33
/* 0x7ffff8b0 */, 0x353a2a2e, 0x666c693d, 0x30313b33, 0x353a2a2e
/* 0x7ffff8c0 */, 0x666c763d, 0x30313b33, 0x353a2a2e, 0x676c3d30
/* 0x7ffff8d0 */, 0x313b3335, 0x3a2a2e64, 0x6c3d3031, 0x3b33353a
/* 0x7ffff8e0 */, 0x2a2e7863, 0x663d3031, 0x3b33353a, 0x2a2e7877
/* 0x7ffff8f0 */, 0x643d3031, 0x3b33353a, 0x2a2e7975, 0x763d3031
/* 0x7ffff900 */, 0x3b33353a, 0x2a2e6367, 0x6d3d3031, 0x3b33353a
/* 0x7ffff910 */, 0x2a2e656d, 0x663d3031, 0x3b33353a, 0x2a2e6f67
/* 0x7ffff920 */, 0x763d3031, 0x3b33353a, 0x2a2e6f67, 0x783d3031
/* 0x7ffff930 */, 0x3b33353a, 0x2a2e6161, 0x633d3030, 0x3b33363a
/* 0x7ffff940 */, 0x2a2e6175, 0x3d30303b, 0x33363a2a, 0x2e666c61
/* 0x7ffff950 */, 0x633d3030, 0x3b33363a, 0x2a2e6d34, 0x613d3030
/* 0x7ffff960 */, 0x3b33363a, 0x2a2e6d69, 0x643d3030, 0x3b33363a
/* 0x7ffff970 */, 0x2a2e6d69, 0x64693d30, 0x303b3336, 0x3a2a2e6d
/* 0x7ffff980 */, 0x6b613d30, 0x303b3336, 0x3a2a2e6d, 0x70333d30
/* 0x7ffff990 */, 0x303b3336, 0x3a2a2e6d, 0x70633d30, 0x303b3336
/* 0x7ffff9a0 */, 0x3a2a2e6f, 0x67673d30, 0x303b3336, 0x3a2a2e72
/* 0x7ffff9b0 */, 0x613d3030, 0x3b33363a, 0x2a2e7761, 0x763d3030
/* 0x7ffff9c0 */, 0x3b33363a, 0x2a2e6f67, 0x613d3030, 0x3b33363a
/* 0x7ffff9d0 */, 0x2a2e6f70, 0x75733d30, 0x303b3336, 0x3a2a2e73
/* 0x7ffff9e0 */, 0x70783d30, 0x303b3336, 0x3a2a2e78, 0x7370663d
/* 0x7ffff9f0 */, 0x30303b33, 0x363a004c, 0x414e473d, 0x656e5f55
/* 0x7ffffa00 */, 0x532e5554, 0x462d3800, 0x4c435f50, 0x41504552
/* 0x7ffffa10 */, 0x3d7a685f, 0x434e2e55, 0x54462d38, 0x00494d5f
/* 0x7ffffa20 */, 0x434f4e46, 0x49475f50, 0x48415345, 0x3d310055
/* 0x7ffffa30 */, 0x5345524e, 0x414d453d, 0x6c697777, 0x00484f4d
/* 0x7ffffa40 */, 0x453d2f68, 0x6f6d652f, 0x6c697777, 0x0057494e
/* 0x7ffffa50 */, 0x444f5750, 0x4154483d, 0x3200474a, 0x535f4445
/* 0x7ffffa60 */, 0x4255475f, 0x544f5049, 0x43533d4a, 0x53204552
/* 0x7ffffa70 */, 0x524f523b, 0x4a53204c, 0x4f47004f, 0x50414d5f
/* 0x7ffffa80 */, 0x53574954, 0x43485f50, 0x52454649, 0x583d2f68
/* 0x7ffffa90 */, 0x6f6d652f, 0x6c697777, 0x2f2e6f70, 0x616d2f64
/* 0x7ffffaa0 */, 0x65666175, 0x6c740058, 0x41555448, 0x4f524954
/* 0x7ffffab0 */, 0x593d2f72, 0x756e2f75, 0x7365722f, 0x31303030
/* 0x7ffffac0 */, 0x2f67646d, 0x2f586175, 0x74686f72, 0x69747900
/* 0x7ffffad0 */, 0x54564d5f, 0x484f4d45, 0x3d2f6d65, 0x6469612f
/* 0x7ffffae0 */, 0x6c697777, 0x2f77696e, 0x646f7773, 0x2f776f72
/* 0x7ffffaf0 */, 0x6b737061, 0x63652f73, 0x696d756c, 0x61746f72
/* 0x7ffffb00 */, 0x2f74766d, 0x00475047, 0x5f414745, 0x4e545f49
/* 0x7ffffb10 */, 0x4e464f3d, 0x2f72756e, 0x2f757365, 0x722f3130
/* 0x7ffffb20 */, 0x30302f67, 0x6e757067, 0x2f532e67, 0x70672d61
/* 0x7ffffb30 */, 0x67656e74, 0x3a303a31, 0x004d414e, 0x50415448
/* 0x7ffffb40 */, 0x3d3a2f68, 0x6f6d652f, 0x6c697777, 0x2f2e6f70
/* 0x7ffffb50 */, 0x616d2f64, 0x65666175, 0x6c742f6d, 0x616e0058
/* 0x7ffffb60 */, 0x44475f53, 0x45535349, 0x4f4e5f54, 0x5950453d
/* 0x7ffffb70 */, 0x78313100, 0x4c4f474e, 0x414d453d, 0x6c697777
/* 0x7ffffb80 */, 0x00584447, 0x5f534553, 0x53494f4e, 0x5f444553
/* 0x7ffffb90 */, 0x4b544f50, 0x3d756275, 0x6e747500, 0x5057443d
/* 0x7ffffba0 */, 0x2f6d6564, 0x69612f6c, 0x6977772f, 0x77696e64
/* 0x7ffffbb0 */, 0x6f77732f, 0x776f726b, 0x73706163, 0x652f7a6b
/* 0x7ffffbc0 */, 0x6d697073, 0x2f6d6970, 0x732d6369, 0x72637569
/* 0x7ffffbd0 */, 0x74730047, 0x544b5f4d, 0x4f44554c, 0x45533d67
/* 0x7ffffbe0 */, 0x61696c3a, 0x61746b2d, 0x62726964, 0x67650053
/* 0x7ffffbf0 */, 0x53485f41, 0x47454e54, 0x5f504944, 0x3d323039
/* 0x7ffffc00 */, 0x31004c43, 0x5f4d4f4e, 0x45544152, 0x593d7a68
/* 0x7ffffc10 */, 0x5f434e2e, 0x5554462d, 0x38004445, 0x534b544f
/* 0x7ffffc20 */, 0x505f5345, 0x5353494f, 0x4e3d7562, 0x756e7475
/* 0x7ffffc30 */, 0x00584d4f, 0x44494649, 0x4552533d, 0x40696d3d
/* 0x7ffffc40 */, 0x66636974, 0x78005353, 0x485f4155, 0x54485f53
/* 0x7ffffc50 */, 0x4f434b3d, 0x2f72756e, 0x2f757365, 0x722f3130
/* 0x7ffffc60 */, 0x30302f6b, 0x65797269, 0x6e672f73, 0x7368004c
/* 0x7ffffc70 */, 0x435f4e41, 0x4d453d7a, 0x685f434e, 0x2e555446
/* 0x7ffffc80 */, 0x2d380047, 0x4e4f4d45, 0x5f534845, 0x4c4c5f53
/* 0x7ffffc90 */, 0x45535349, 0x4f4e5f4d, 0x4f44453d, 0x7562756e
/* 0x7ffffca0 */, 0x7475004c, 0x435f4144, 0x44524553, 0x533d7a68
/* 0x7ffffcb0 */, 0x5f434e2e, 0x5554462d, 0x3800464f, 0x5243455f
/* 0x7ffffcc0 */, 0x50595448, 0x4f4e5f56, 0x45523d33, 0x2e38004d
/* 0x7ffffcd0 */, 0x414e4441, 0x544f5259, 0x5f504154, 0x483d2f75
/* 0x7ffffce0 */, 0x73722f73, 0x68617265, 0x2f67636f, 0x6e662f75
/* 0x7ffffcf0 */, 0x62756e74, 0x752e6d61, 0x6e646174, 0x6f72792e
/* 0x7ffffd00 */, 0x70617468, 0x00515434, 0x5f494d5f, 0x4d4f4455
/* 0x7ffffd10 */, 0x4c453d66, 0x63697478, 0x004e4f44, 0x453d6874
/* 0x7ffffd20 */, 0x7470733a, 0x2f2f6574, 0x682d6d61, 0x696e6e65
/* 0x7ffffd30 */, 0x742e672e, 0x616c6368, 0x656d792e, 0x636f6d2f
/* 0x7ffffd40 */, 0x76322f6f, 0x306d4852, 0x354a4e41, 0x33574a4a
/* 0x7ffffd50 */, 0x465f4346, 0x65662d59, 0x654b5379, 0x764c2d6c
/* 0x7ffffd60 */, 0x4f714700, 0x5a4f4b52, 0x41544553, 0x5f535444
/* 0x7ffffd70 */, 0x4c49423d, 0x2f6d6564, 0x69612f6c, 0x6977772f
/* 0x7ffffd80 */, 0x77696e64, 0x6f77732f, 0x776f726b, 0x73706163
/* 0x7ffffd90 */, 0x652f7a6b, 0x6d697073, 0x2f5a6f4b, 0x72617465
/* 0x7ffffda0 */, 0x732f7a6f, 0x6b726174, 0x65735f73, 0x74646c69
/* 0x7ffffdb0 */, 0x622f7374, 0x646c6962, 0x00504b47, 0x5f434f4e
/* 0x7ffffdc0 */, 0x4649475f, 0x50415448, 0x3d2f686f, 0x6d652f6c
/* 0x7ffffdd0 */, 0x6977772f, 0x2e6f7061, 0x6d2f6465, 0x6661756c
/* 0x7ffffde0 */, 0x742f6c69, 0x622f706b, 0x67636f6e, 0x6669673a
/* 0x7ffffdf0 */, 0x0047544b, 0x5f494d5f, 0x4d4f4455, 0x4c453d66
/* 0x7ffffe00 */, 0x63697478, 0x00474e4f, 0x4d455f44, 0x45534b54
/* 0x7ffffe10 */, 0x4f505f53, 0x45535349, 0x4f4e5f49, 0x443d7468
/* 0x7ffffe20 */, 0x69732d69, 0x732d6465, 0x70726563, 0x61746564
/* 0x7ffffe30 */, 0x006e6f5f, 0x70726f78, 0x793d6c6f, 0x63616c68
/* 0x7ffffe40 */, 0x6f73742c, 0x3132372e, 0x302e302e, 0x302f382c
/* 0x7ffffe50 */, 0x3a3a3100, 0x5844475f, 0x4d454e55, 0x5f505245
/* 0x7ffffe60 */, 0x4649583d, 0x676e6f6d, 0x652d0046, 0x4f524345
/* 0x7ffffe70 */, 0x5f43433d, 0x2f757372, 0x2f62696e, 0x2f672b2b
/* 0x7ffffe80 */, 0x00584447, 0x5f434f4e, 0x4649475f, 0x44495253
/* 0x7ffffe90 */, 0x3d2f6574, 0x632f7864, 0x672f7864, 0x672d7562
/* 0x7ffffea0 */, 0x756e7475, 0x3a2f6574, 0x632f7864, 0x6700434f
/* 0x7ffffeb0 */, 0x4c4f5254, 0x45524d3d, 0x74727565, 0x636f6c6f
/* 0x7ffffec0 */, 0x72004f43, 0x414d4c5f, 0x544f504c, 0x4556454c
/* 0x7ffffed0 */, 0x5f504154, 0x483d2f68, 0x6f6d652f, 0x6c697777
/* 0x7ffffee0 */, 0x2f2e6f70, 0x616d2f64, 0x65666175, 0x6c742f6c
/* 0x7ffffef0 */, 0x69622f74, 0x6f706c65, 0x76656c00, 0x51545f41
/* 0x7fffff00 */, 0x43434553, 0x53494249, 0x4c495459, 0x3d310043
/* 0x7fffff10 */, 0x414d4c5f, 0x4c445f4c, 0x49425241, 0x52595f50
/* 0x7fffff20 */, 0x4154483d, 0x2f686f6d, 0x652f6c69, 0x77772f2e
/* 0x7fffff30 */, 0x6f70616d, 0x2f646566, 0x61756c74, 0x2f6c6962
/* 0x7fffff40 */, 0x2f737475, 0x626c6962, 0x733a2f75, 0x73722f6c
/* 0x7fffff50 */, 0x6f63616c, 0x2f6c6962, 0x2f6f6361, 0x6d6c2f34
/* 0x7fffff60 */, 0x2e30382e, 0x312f7374, 0x75626c69, 0x62733a2f
/* 0x7fffff70 */, 0x7573722f, 0x6c69622f, 0x6f63616d, 0x6c2f7374
/* 0x7fffff80 */, 0x75626c69, 0x62730053, 0x45535349, 0x4f4e5f4d
/* 0x7fffff90 */, 0x414e4147, 0x45523d6c, 0x6f63616c, 0x2f6c6977
/* 0x7fffffa0 */, 0x773a402f, 0x746d702f, 0x2e494345, 0x2d756e69
/* 0x7fffffb0 */, 0x782f3231, 0x33372c75, 0x6e69782f, 0x6c697777
/* 0x7fffffc0 */, 0x3a2f746d, 0x702f2e49, 0x43452d75, 0x6e69782f
/* 0x7fffffd0 */, 0x32313337, 0x00534845, 0x4c4c3d2f, 0x62696e2f
/* 0x7fffffe0 */, 0x62617368, 0x002e2f74, 0x6573742d, 0x76656374
/* 0x7ffffff0 */, 0x6f72732f, 0x61626300, 0x00000000, 0x00000000
];
        // init argc,  argv, aux on stack
        for (pos, v) in data.iter().enumerate() {
            store_mem(sp + 4 * (pos as u32), *v); // argc = 0 (argument count)
        }

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

    pub fn get_registers_bytes(&mut self) -> [u8; 36 * 4] {
        let mut regs_bytes_be = [0u8; 36 * 4];
        for i in 0..32 {
            regs_bytes_be[i * 4..i * 4 + 4].copy_from_slice(&self.registers[i].to_be_bytes());
        }

        regs_bytes_be[32 * 4..32 * 4 + 4].copy_from_slice(&self.lo.to_be_bytes());
        regs_bytes_be[33 * 4..33 * 4 + 4].copy_from_slice(&self.hi.to_be_bytes());
        regs_bytes_be[34 * 4..34 * 4 + 4].copy_from_slice(&self.heap.to_be_bytes());
        regs_bytes_be[35 * 4..35 * 4 + 4].copy_from_slice(&self.pc.to_be_bytes());
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

        self.state.dump_info = true;

        println!("syscall {}", syscall_num);

        match syscall_num {
            4020 => {
                //read preimage (getpid)
                //self.state.load_preimage(self.block_path.clone())
            }
            4210 |
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
                } else {
                    if rtv == 0b10001 {
                        // bal  000001 00000 10001 offset
                        self.state.registers[31] = self.state.pc + 8;
                        true
                    } else {
                        false
                    }
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
            self.state.next_pc = self.state.next_pc + 4;
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
        let fun = insn & 0x3f;
        if opcode == 0 || opcode == 0x1c || (opcode == 0x1F && fun == 0x20) {
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

        if opcode == 0 && fun == 0x34 && val == 1 {
            self.handle_trap();
        }

        // stupid sc, write a 1 to rt
        if opcode == 0x38 && rt_reg != 0 {
            self.state.registers[rt_reg as usize] = 1;
        }

        if opcode == 0x33 {  //pref
            self.handle_rd(0, val, false);
            return;
        }

        // write memory
        if store_addr != 0xffFFffFF {
            //let value_prev = self.state.memory.get_memory(store_addr);
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
                } else if fun == 0b111011 {
                    //rdhwr
                    let rd = (insn >> 11) & 0x1F;
                    if rd == 0 {
                        return 1;  // cpu number
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

        panic!("invalid instruction, opcode: {:X} {:X} {:X}", opcode, insn,  self.state.pc);
    }

    pub fn step(&mut self) {
        let dump: bool = self.state.dump_info;
        self.state.dump_info = false;

        self.mips_step();
        if dump {
            //println!("pc: {:X} regs: {:X?}\n", self.state.pc, self.state.registers);
        };
    }

    /// the caller should provide a write to write segemnt if proof is true
    pub fn split_segment<W: Write>(
        &mut self,
        proof: bool,
        output: &str,
        new_writer: fn(&str) -> Option<W>,
    ) {
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
                page_hash_root,
            };
            let name = format!("{output}/{}", self.pre_segment_id);
            log::debug!("split: file {}", name);
            let mut f = new_writer(&name).unwrap();
            let data = serde_json::to_vec(&segment).unwrap();
            f.write_all(data.as_slice()).unwrap();
            self.pre_segment_id += 1;
        }

        self.pre_pc = self.state.pc;
        self.pre_image_id = image_id;
        self.pre_hash_root = page_hash_root;
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
