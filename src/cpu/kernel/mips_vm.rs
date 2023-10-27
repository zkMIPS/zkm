#![allow(arithmetic_overflow)]
extern crate alloc;
use std::collections::HashMap;
use alloc::collections::BTreeMap;

use prettytable::{Table, Row, Cell, Attr, color};

use std::ops::BitOr;
use std::ops::BitAnd;

pub enum Faults {
    BadAddress,
    BadJump,
    SyntaxError,
    NoFault
}

use super::load_elf::Program;
use anyhow::{anyhow, bail, Context, Result};
use elf::{endian::BigEndian, file::Class, ElfBytes};
pub const WORD_SIZE: usize = core::mem::size_of::<u32>();

/// Instruction represetation
#[derive(Default, Debug)]
pub struct Instruction {
    pub insn: u32,
    pub op: u8,
    pub itype: InstructionType,
}

impl Instruction {
    pub fn new(insn: u32, op: u8, itype: InstructionType) -> Self {
        Instruction {
            insn,
            op,
            itype,
        }
    }
}

#[derive(Debug)]
pub enum InstructionType {
    RType,
    IType,
    JType,
    Special
}


impl Default for InstructionType {
    fn default() -> Self { InstructionType::Special }
}

pub struct Processor {
    pub program: Program,
    pub gpr: [i32; 32],
    pub pc: u32,
    pub hi: u32,
    pub lo: u32,
    pub labels: HashMap<String, u32>,
    pub instructions: Vec<Instruction>,
    pub memory: [u32; 65536],
    pub is_running: bool
}

impl Processor {
    /// Initialize with basic constants
    pub fn new(p: Program) -> Processor {
        let mut proc = Processor {
            pc: p.entry,
            program: p,
            gpr: [0; 32],
            hi: 0x0,
            lo: 0x0,
            instructions: Vec::new(),
            labels: HashMap::new(),
            memory: [0; 65536],
            is_running: true
        };
        // proc.gpr[29] = 0x7fffeffc;
        proc
    }

    pub fn set_value(&mut self, destination_gpr: u8, new_value: i32) {
        if destination_gpr != 0 {
            self.gpr[destination_gpr as usize] = new_value;
        }
    }

    pub fn get_value(&self, source_gpr: u8) -> i32 {
        self.gpr[source_gpr as usize]
    }

    pub fn add_label(&mut self, label: String) {
        self.labels.insert(label.replace(':', ""), (self.instructions.len() * 4) as u32 + 0x00400000);
    }

    pub fn add_instruction(&mut self, instr: Instruction) {
        self.instructions.push(instr);
    }

    fn get_instruction(&self, address: u32) -> Option<Instruction> {
        // self.instructions.get((address - 0x00400000) as usize / 4)
        match self.program.image.get(&address) {
            Some(insn) => parse_insn_type(*insn),
            _ => None,
        }
    }

    fn store_word(&mut self, address: u32, word: u32) {
        self.memory[(address - 0x10010000) as usize / 4] = word;
    }

    fn load_word(&self, address: u32) -> u32 {
        self.memory[(address - 0x10010000) as usize / 4]
    }

    pub fn next(&mut self) {
        let current: Option<Instruction> = self.get_instruction(self.pc);
        if let Some(current) = current {
            let insn = current.insn;
            let op = current.op;
            let mut branch: bool = false;
            match current.itype {
                InstructionType::IType => {
                    match op {
                        0b001101 => {
                            let (dest, source, immediate) = get_dest_src_imm(&current);
                            self.set_value(dest, self.get_value(source).bitor(immediate as i32));
                        },
                        0b001001 => {
                            let (dest, source, immediate) = get_dest_src_imm(instr.instruction.as_str());
                            self.set_value(dest, self.get_value(source) + immediate as i32);
                        },
                        "slti" => {
                            let (dest, source, immediate) = get_dest_src_imm(instr.instruction.as_str());
                            if self.get_value(source) > immediate as i32 {
                                self.set_value(dest, 0);
                            } else {
                                self.set_value(dest, 1);
                            }
                        },
                        "sltiu" => {
                            let (dest, source, immediate) = get_dest_src_imm(instr.instruction.as_str());
                            if self.get_value(source) as u32 > immediate as u32 {
                                self.set_value(dest, 0);
                            } else {
                                self.set_value(dest, 1);
                            }
                        },
                        "andi" => {
                            let (dest, source, immediate) = get_dest_src_imm(instr.instruction.as_str());
                            self.set_value(dest, self.get_value(source) & immediate as i32);
                        },
                        "lui" => {
                            let (dest, immediate) = get_dest_imm(instr.instruction.as_str());
                            self.set_value(dest, immediate << 16);
                        },
                        _ => {
                            panic!("Unhandled I-type instruction!");
                        }
                    }
                },
                InstructionType::RType => {
                    let (rd, rs, rt) = get_rs_rt_rd(instr.instruction.as_str());
                    match opword {
                        "and" => {
                            let temp = self.get_value(rs).bitand(self.get_value(rt));
                            self.set_value(rd, temp);
                        },
                        "or" => {
                            self.set_value(rd, self.get_value(rs) & self.get_value(rt));
                        },
                        "nor" => {
                            self.set_value(rd, !(self.get_value(rs) | self.get_value(rt)));
                        },
                        "add" => {
                            self.set_value(rd, self.get_value(rs) + self.get_value(rt));
                        },
                        "sub" => {
                            self.set_value(rd, self.get_value(rs) - self.get_value(rt));
                        },
                        _ => {
                            panic!("Unhandled R-type instruction!");
                        }
                    }
                },
                InstructionType::JType => {
                    match opword {
                        "j" => {
                            let label = get_label(instr.instruction.as_str());
                            if self.labels.contains_key(label.as_str()) {
                                branch = true;
                                self.pc = self.labels.get(label.as_str()).clone().unwrap().clone();
                            }
                        },
                        "jr" => {
                            let rt = get_rt(instr.instruction.as_str());
                            self.pc = self.get_value(rt) as u32;
                        },
                        "jal" => {
                            let label = get_label(instr.instruction.as_str());
                            if self.labels.contains_key(label.as_str()) {
                                branch = true;
                                self.set_value(31, (self.pc) as i32);
                                self.pc = self.labels.get(label.as_str()).clone().unwrap().clone();
                            }
                        },
                        _ => {
                            unreachable!();
                        }
                    }
                },
                InstructionType::Special => {
                    match opword {
                        "nop" => {
                            // Do nothing
                        },
                        "srl" => {
                            let (rd, rs, count) = get_rd_rs_count(instr.instruction.as_str());
                            self.set_value(rd, self.get_value(rs) >> count);
                        },
                        "sll" => {
                            let (rd, rs, count) = get_rd_rs_count(instr.instruction.as_str());
                            self.set_value(rd, self.get_value(rs) << count);
                        },
                        "sw" => {
                            let (source, target) = get_memory_register(instr.instruction.as_str());
                            self.store_word(self.get_value(target) as u32, self.get_value(source) as u32);
                        },
                        "lw" => {
                            let (target, source) = get_memory_register(instr.instruction.as_str());
                            self.set_value(target, self.load_word(self.get_value(source) as u32) as i32);
                        },
                        _ => {

                        }
                    }
                }
            };
            if !branch {
                self.pc += 4;
            }
        } else {
            self.is_running = false;
        }
    }

     pub fn is_running(&self) -> bool {
        return self.is_running;
    }

    pub fn get_instruction_count(&self) -> usize {
        self.instructions.len()
    }

    pub fn get_pc(&self) -> u32 {
        self.pc
    }

    pub fn print_labels(&self) {
        println!("{:X?}", self.labels);
    }

    pub fn print_state(&self) {
        let mut table = Table::new();
        table.add_row(Row::new(vec![Cell::new("All GPR Values").with_hspan(8)]));
        for i in 0..8 {
            table.add_row(row![
                register_name(i), format_as_word(self.gpr[i as usize] as u32),
                register_name(i + 8), format_as_word(self.gpr[(i + 8) as usize] as u32),
                register_name(i + 16), format_as_word(self.gpr[(i + 16) as usize] as u32),
                register_name(i + 24), format_as_word(self.gpr[(i + 24) as usize] as u32)
            ]);
        }
        table.add_row(Row::new(vec![Cell::new("PC"), Cell::new(format_as_word(self.pc).as_str())
                                        .with_style(Attr::BackgroundColor(color::RED))
                                        .with_style(Attr::Italic(true))
                                        .with_hspan(5)]));
        table.printstd();
    }

    pub fn dump_data_memory(&self, from: u32, to: u32) {
        let mut table = Table::new();
        table.add_row(Row::new(vec![Cell::new(format!("Memory Segment from {:x} to {:x}", from, to).as_str()).with_hspan(2)]));
        for address in (from..to).step_by(4) {
            table.add_row(row![format_as_word(address), format_as_word(self.load_word(address))]);
        }
        table.printstd();
    }
}

pub fn assemble_instruction(word: String) -> u32 {
    let components: Vec<String> = word.split_whitespace().map(|s| s.to_string().replace(',', "")).collect();
    match components.get(0).unwrap().to_lowercase().as_str() {
        "addi" => {
            let rd: u8 = parse_register(components.get(1).unwrap());
            let rs: u8 = parse_register(components.get(2).unwrap());
            let imm_str = components.get(2).unwrap();
            let mut imm: i16 = 0;
            if imm_str.starts_with("0x") {
            } else {
                imm = i16::from_str_radix(imm_str, 10).unwrap();
            }
            return (0x08 << 32) + (rs << 27) as u32;
        },
        _ => {
            return 0xffff_ffff; // -1
        }
    }
}

pub fn format_as_word(value: u32) -> String {
    format!("{}{:0>8x}", "0x", value)
}

/// Parses a 16-bit immediate into a number representation
/// hex_str: The 16-bit immediate
pub fn parse_hexadecimal(hex_str: &str) -> i32 {
    let hex_str = hex_str.replace("0x", "");
    i32::from_str_radix(hex_str.as_str(), 16).unwrap()
}

pub fn parse_insn_type(insn: u32) -> Option<Instruction> {
    let i_types = vec![
        0b001000u32,
        0b001001,
        0b001010,
        0b001011,
        0b001011,
        0b001101,
        0b001110,
        0b001111
    ];
    let r_types = vec![
        0b100100u32,
        0b100101,
        0b100111,
    ];
    let special_types = vec![
        0b000000u32,
        0b000000,
        0b000010,
        0b100011,
        0b101011,
    ];
    let j_types = vec![
        0b000010u32,
        0b001000,
        0b000011,
    ];
    // let i_types = vec!["addi", "addiu", "slti", "sltiu", "andi", "ori", "xori", "lui"];
    // let r_types = vec!["and", "or", "nor"];
    // let special_types = vec!["nop", "sll", "srl", "lw", "sw"];
    // let j_types = vec!["j", "jr", "jal"];

    let opword = insn >> 26;

    for instr_type in &r_types {
        if opword.eq(instr_type) {
            return Some(Instruction::new(insn, opword, InstructionType::RType))
        }
    }
    for instr_type in &i_types {
        if opword.eq(instr_type) {
            return Some(Instruction::new(insn, opword, InstructionType::IType))
        }
    }
    for instr_type in &j_types {
        if opword.eq(instr_type) {
            return Some(Instruction::new(insn, opword, InstructionType::JType))
        }
    }
    for instr_type in &special_types {
        if opword.eq(instr_type) {
            return Some(Instruction::new(insn, opword, InstructionType::Special))
        }
    }
    return None;
}

pub fn parse_register(register: &str) -> u8 {
    let result: u8 = match register {
        "$zero" => 0,
        "$at" => 1,
        "$v0" => 2,
        "$v1" => 3,
        "$a0" => 4,
        "$a1" => 5,
        "$a2" => 6,
        "$a3" => 7,
        "$t0" => 8,
        "$t1" => 9,
        "$t2" => 10,
        "$t3" => 11,
        "$t4" => 12,
        "$t5" => 13,
        "$t6" => 14,
        "$t7" => 15,
        "$s0" => 16,
        "$s1" => 17,
        "$s2" => 18,
        "$s3" => 19,
        "$s4" => 20,
        "$s5" => 21,
        "$s6" => 22,
        "$s7" => 23,
        "$t8" => 24,
        "$t9" => 25,
        "$k0" => 26,
        "$k1" => 27,
        "$gp" => 28,
        "$sp" => 29,
        "$fp" => 30,
        "$ra" => 31,
        _ => {
            panic!("Invalid register type! {}", register);
        }
    };
    result
}

pub fn register_name(register: u8) -> String {
    let result: &str = match register {
        0 => "$zero",
        1 => "at",
        2 => "v0",
        3 => "v1",
        4 => "a0",
        5 => "a1",
        6 => "a2",
        7 => "a3",
        8 => "t0",
        9 => "t1",
        10 => "t2",
        11 => "t3",
        12 => "t4",
        13 => "t5",
        14 => "t6",
        15 => "t7",
        16 => "s0",
        17 => "s1",
        18 => "s2",
        19 => "s3",
        20 => "s4",
        21 => "s5",
        22 => "s6",
        23 => "s7",
        24 => "t8",
        25 => "t9",
        26 => "k0",
        27 => "k1",
        28 => "gp",
        29 => "sp",
        30 => "fp",
        31 => "ra",
        _ => {
            panic!("Invalid register type! {}", register);
        }
    };
    String::from(result)
}

fn parse_immediate(imm: &String) -> i32 {
    if imm.starts_with("0x") {
        return parse_hexadecimal(imm.as_str());
    } else {
        return imm.parse::<i32>().unwrap();
    }
}

pub fn get_dest_src_imm(insn: &Instruction) -> (u8, u8, i32) {
    let components: Vec<String> = word.split_whitespace().map(|s| s.to_string().replace(',', "")).collect();
    let dest: u8 = parse_register(components.get(1).unwrap());
    let source: u8 = parse_register(components.get(2).unwrap());
    return (dest, source, parse_immediate(components.get(3).unwrap()));
}

pub fn get_dest_imm(word: &str) -> (u8, i32) {
    let components: Vec<String> = word.split_whitespace().map(|s| s.to_string().replace(',', "")).collect();
    let dest: u8 = parse_register(components.get(1).unwrap());
    let immediate: i32 = parse_hexadecimal(components.get(2).unwrap());
    return (dest, immediate);
}

pub fn get_rs_rt_rd(word: &str) -> (u8, u8, u8) {
    let components: Vec<String> = word.split_whitespace().map(|s| s.to_string().replace(',', "")).collect();
    let rd: u8 = parse_register(components.get(1).unwrap());
    let rs: u8 = parse_register(components.get(2).unwrap());
    let rt: u8 = parse_register(components.get(3).unwrap());
    return (rd, rs, rt);
}

pub fn get_rd_rs_count(word: &str) -> (u8, u8, u16) {
    let components: Vec<String> = word.split_whitespace().map(|s| s.to_string().replace(',', "")).collect();
    let rd: u8 = parse_register(components.get(1).unwrap());
    let rs: u8 = parse_register(components.get(2).unwrap());
    let count: u16 = components.get(3).unwrap().parse::<u16>().unwrap();
    return (rd, rs, count);
}

pub fn get_label(word: &str) -> String {
    let components: Vec<String> = word.split_whitespace().map(|s| s.to_string().replace(',', "")).collect();
    components.get(1).unwrap().clone()
}

pub fn get_rt(word: &str) -> u8 {
    let components: Vec<String> = word.split_whitespace().map(|s| s.to_string().replace(',', "")).collect();
    let target = parse_register(components.get(1).unwrap());
    return target;
}

/// Returns the register that holds the address of the memory location being read or written to.
pub fn get_memory_register(word: &str) -> (u8, u8) {
    let components: Vec<String> = word.split_whitespace().map(|s| s.to_string().replace(',', "")).collect();
    let target = parse_register(components.get(1).unwrap());
    let target2 = parse_register(components.get(2).unwrap().replace("(", "").replace(")", "").as_str());
    return (target, target2);
}

pub fn sign_extend(input: u32) -> i32 {
    ((input as i32) << 16) >> 16
}

pub fn zero_extend(input: u16) -> u32 {
    (input as u32) << 16
}

#[cfg(test)]
mod test {
    use std::fs::File;
    use std::io::BufReader;
    use std::io::Read;

    use crate::cpu::kernel::load_elf::*;
    use crate::cpu::kernel::mips_vm::*;

    #[test]
    fn test_processor() {
        let mut reader = BufReader::new(File::open("test-vectors/hello").unwrap());
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).unwrap();
        let max_mem = 0x40000000;
        let p = Program::load_elf(&buffer, max_mem).unwrap();
        println!("entry: {}", p.entry);

        let mut proc: Processor = Processor::new(p);

        while proc.is_running() {
            proc.next();
        }

        proc.print_state();

        proc.dump_data_memory(0x10010000, 0x1001000c);
    }
}
