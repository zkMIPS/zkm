extern crate alloc;
use alloc::collections::BTreeMap;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{self};
use std::io::Read;
use zkm_emulator::memory::WORD_SIZE;
use zkm_emulator::state::{Segment, REGISTERS_START};
pub const PAGE_SIZE: u32 = 4096;

/// A MIPS program
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Default)]
pub struct Program {
    /// The entrypoint of the program, PC
    pub entry: u32,
    pub next_pc: usize,
    /// The initial memory image
    pub image: BTreeMap<u32, u32>,
    pub gprs: [usize; 32],
    pub lo: usize,
    pub hi: usize,
    pub heap: usize,
    pub brk: usize,
    pub local_user: usize,
    pub end_pc: usize,
    pub step: usize,
    pub image_id: [u8; 32],
    pub pre_image_id: [u8; 32],
    pub pre_hash_root: [u8; 32],
    pub page_hash_root: [u8; 32],
    pub input_stream: Vec<Vec<u8>>,
    pub input_stream_ptr: usize,
    pub public_values_stream: Vec<u8>,
    pub public_values_stream_ptr: usize,
}

impl Program {
    pub fn load_block(&mut self, blockpath: &str) -> Result<bool> {
        let content = fs::read(blockpath).expect("Read file failed");

        let mut map_addr = 0x30000000;
        for i in (0..content.len()).step_by(WORD_SIZE) {
            let mut word = 0;
            // Don't read past the end of the file.
            let len = core::cmp::min(content.len() - i, WORD_SIZE);
            for j in 0..len {
                let offset = i + j;
                let byte = content.get(offset).context("Invalid block offset")?;
                word |= (*byte as u32) << (j * 8);
            }
            self.image.insert(map_addr, word);
            map_addr += 4;
        }

        Ok(true)
    }

    pub fn load_segment<T: Read>(reader: T) -> Result<Program> {
        let segment: Segment = serde_json::from_reader(reader).unwrap();

        let entry = segment.pc;
        let image = segment.mem_image;
        let end_pc = segment.end_pc as usize;

        let mut gprs: [usize; 32] = [0; 32];

        for i in 0..32 {
            let data = image.get(&(REGISTERS_START + (i << 2) as u32)).unwrap();
            gprs[i] = data.to_be() as usize;
        }

        let lo: usize = image
            .get(&(REGISTERS_START + (32 << 2) as u32))
            .unwrap()
            .to_be() as usize;
        let hi: usize = image
            .get(&(REGISTERS_START + (33 << 2) as u32))
            .unwrap()
            .to_be() as usize;
        let heap: usize = image
            .get(&(REGISTERS_START + (34 << 2) as u32))
            .unwrap()
            .to_be() as usize;
        let pc: usize = image
            .get(&(REGISTERS_START + (35 << 2) as u32))
            .unwrap()
            .to_be() as usize;
        let next_pc: usize = image
            .get(&(REGISTERS_START + (36 << 2) as u32))
            .unwrap()
            .to_be() as usize;

        let brk: usize = image
            .get(&(REGISTERS_START + (37 << 2) as u32))
            .unwrap()
            .to_be() as usize;

        let local_user: usize = image
            .get(&(REGISTERS_START + (38 << 2) as u32))
            .unwrap()
            .to_be() as usize;

        let page_hash_root = segment.page_hash_root;

        assert!(pc as u32 == segment.pc);

        log::trace!(
            "load segment pc: {} image: {:?} gprs: {:?} lo: {} hi: {} heap:{} range: ({} -> {})",
            segment.pc,
            segment.image_id,
            gprs,
            lo,
            hi,
            heap,
            pc,
            end_pc
        );
        Ok(Program {
            entry,
            next_pc,
            image,
            gprs,
            lo,
            hi,
            heap,
            brk,
            local_user,
            end_pc,
            step: segment.step as usize,
            image_id: segment.image_id,
            pre_image_id: segment.pre_image_id,
            pre_hash_root: segment.pre_hash_root,
            page_hash_root,
            input_stream: segment.input_stream,
            input_stream_ptr: segment.input_stream_ptr,
            public_values_stream: segment.public_values_stream,
            public_values_stream_ptr: segment.public_values_stream_ptr,
        })
    }
}
