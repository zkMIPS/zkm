#![allow(clippy::extra_unused_lifetimes)]
use std::cell::RefCell;
pub const WORD_SIZE: usize = core::mem::size_of::<u32>();
pub const INIT_SP: u32 = 0x7fffd000;
use super::page::MAX_MEMORY;
use crate::page::{CachedPage, PAGE_ADDR_MASK, PAGE_ADDR_SIZE, PAGE_SIZE};
use itertools::Itertools;
use lazy_static::lazy_static;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::packed::PackedField;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::poseidon::Poseidon;
use std::collections::BTreeMap;
use std::io::Read;
use std::rc::Rc;

pub const HASH_ADDRESS_BASE: u32 = 0x80000000;
pub const HASH_ADDRESS_END: u32 = 0x81020000;
pub const ROOT_HASH_ADDRESS_BASE: u32 = 0x81021000;
pub const END_PC_ADDRESS: u32 = ROOT_HASH_ADDRESS_BASE + 4 * 8;
pub const REGISTERS_OFFSET: usize = 0x400;

/// Operation to memory access, Read/Write
#[derive(Copy, Clone, Debug)]
pub enum MemoryOperation {
    Read,
    Write,
}

pub const SPONGE_RATE: usize = 8;
pub const SPONGE_CAPACITY: usize = 4;
pub const SPONGE_WIDTH: usize = SPONGE_RATE + SPONGE_CAPACITY;
pub(crate) const POSEIDON_WIDTH_BYTES: usize = 48; // 12 * 4
pub(crate) const POSEIDON_WIDTH_U32S: usize = POSEIDON_WIDTH_BYTES / 4;
pub(crate) const POSEIDON_WIDTH_MINUS_DIGEST: usize = SPONGE_WIDTH - POSEIDON_DIGEST;
pub(crate) const POSEIDON_RATE_BYTES: usize = SPONGE_RATE * 4;
pub(crate) const POSEIDON_RATE_U32S: usize = POSEIDON_RATE_BYTES / 4;
pub(crate) const POSEIDON_CAPACITY_BYTES: usize = 64;
pub(crate) const POSEIDON_CAPACITY_U32S: usize = POSEIDON_CAPACITY_BYTES / 4;
pub(crate) const POSEIDON_DIGEST_BYTES: usize = 32;
pub(crate) const POSEIDON_DIGEST: usize = 4;

pub fn poseidon(inputs: &[u8]) -> [u64; POSEIDON_DIGEST] {
    let l = inputs.len();
    let chunks = l / POSEIDON_RATE_BYTES + 1;
    let mut input = inputs.to_owned();
    input.resize(chunks * POSEIDON_RATE_BYTES, 0);

    // pad10*1 rule
    if l % POSEIDON_RATE_BYTES == POSEIDON_RATE_BYTES - 1 {
        // Both 1s are placed in the same byte.
        input[l] = 0b10000001;
    } else {
        input[l] = 1;
        input[chunks * POSEIDON_RATE_BYTES - 1] = 0b10000000;
    }

    let mut state: [GoldilocksField; 12] = [PackedField::ZEROS; SPONGE_WIDTH];
    for block in input.chunks(POSEIDON_RATE_BYTES) {
        let block_u32s = (0..SPONGE_RATE)
            .map(|i| {
                Field::from_canonical_u32(u32::from_le_bytes(
                    block[i * 4..(i + 1) * 4].to_vec().try_into().unwrap(),
                ))
            })
            .collect_vec();
        state[..SPONGE_RATE].copy_from_slice(&block_u32s);
        let output = Poseidon::poseidon(state);
        state.copy_from_slice(&output);
    }

    let hash = state
        .iter()
        .take(POSEIDON_DIGEST)
        .map(|x| x.to_canonical_u64())
        .collect_vec();

    hash.try_into().unwrap()
}

pub fn hash_page(data: &[u8; 4096]) -> [u8; 32] {
    let hash_u64s = poseidon(data);
    let hash = hash_u64s
        .iter()
        .flat_map(|&num| num.to_le_bytes())
        .collect::<Vec<_>>();

    hash.try_into().unwrap()
}

fn zero_hash() -> [u8; 32] {
    let zeros = [0u8; 4096];

    hash_page(&zeros)
}

fn compute_const_hash_pages(hash: &mut [[u8; 4096]; 3], level: usize) -> [u8; 32] {
    if level == 0 {
        return zero_hash();
    }

    let base_hash = compute_const_hash_pages(hash, level - 1);
    log::trace!("level {} base hash {:?}", level - 1, base_hash);

    for i in 0..(4096 >> 5) {
        hash[level - 1][i << 5..(i << 5) + 32].copy_from_slice(&base_hash);
    }

    hash_page(&hash[level - 1])
}

lazy_static! {
    static ref CONST_HASH_PAGES: [[u8; 4096]; 3] = {
        let mut hash = [[0u8; 4096]; 3];
        let _ = compute_const_hash_pages(&mut hash, 3);
        hash
    };
}

#[derive(Debug)]
pub struct Memory {
    /// page index -> cached page
    pages: BTreeMap<u32, Rc<RefCell<CachedPage>>>,

    // two caches: we often read instructions from one page, and do memory things with another page.
    // this prevents map lookups each instruction
    last_page_keys: [Option<u32>; 2],
    last_page: [Option<Rc<RefCell<CachedPage>>>; 2],

    // for implement std::io::Read trait
    addr: u32,
    count: u32,

    rtrace: BTreeMap<u32, [u8; PAGE_SIZE]>,
    wtrace: [BTreeMap<u32, Rc<RefCell<CachedPage>>>; 3],
}

pub fn hash_cached_page(page: &Rc<RefCell<CachedPage>>) -> [u8; 32] {
    let data = page.borrow().data;
    hash_page(&data)
}

impl Default for Memory {
    fn default() -> Self {
        Self::new()
    }
}

impl Memory {
    pub fn new() -> Self {
        Self {
            pages: BTreeMap::new(),

            last_page_keys: Default::default(), // default to invalid keys, to not match any pages
            last_page: Default::default(),

            addr: 0,
            count: 0,
            rtrace: BTreeMap::new(),
            wtrace: [BTreeMap::new(), BTreeMap::new(), BTreeMap::new()],
        }
    }

    pub fn page_count(&self) -> usize {
        self.pages.len()
    }

    pub fn for_each_page<T: Fn(u32, &Rc<RefCell<CachedPage>>) -> Result<(), String>>(
        &mut self,
        handler: T,
    ) -> Result<(), String> {
        for (page_index, cached_page) in self.pages.iter() {
            let r = handler(*page_index, cached_page);
            r?
        }

        Ok(())
    }

    fn page_lookup(&mut self, page_index: u32) -> Option<Rc<RefCell<CachedPage>>> {
        // find cache first
        if Some(page_index) == self.last_page_keys[0] {
            return self.last_page[0].clone();
        }
        if Some(page_index) == self.last_page_keys[1] {
            return self.last_page[1].clone();
        }

        match self.pages.get(&page_index) {
            None => None,
            Some(cached_page) => {
                self.last_page_keys[1] = self.last_page_keys[0];
                self.last_page[1] = self.last_page[0].take();

                self.last_page_keys[0] = Some(page_index);
                self.last_page[0] = Some(cached_page.clone());

                self.last_page[0].clone()
            }
        }
    }

    pub fn set_hash_trace<'a>(&mut self, page_index: u32, level: usize) {
        let hash_addr = (page_index << 5) + MAX_MEMORY as u32;
        let page_index = hash_addr >> PAGE_ADDR_SIZE;
        let cached_page: Option<Rc<RefCell<CachedPage>>> = self.page_lookup(page_index);
        let page = match cached_page {
            None => self.alloc_hash_page(page_index, level),
            Some(page) => page,
        };

        self.rtrace
            .entry(page_index)
            .or_insert_with(|| page.borrow().clone().data);

        if level < 2 {
            self.set_hash_trace(page_index, level + 1);
        }
    }

    pub fn get_memory(&mut self, addr: u32) -> u32 {
        // addr must be aligned to 4 bytes
        if addr & 0x3 != 0 {
            panic!("unaligned memory access: {:x?}", addr);
        }

        let page_index = addr >> PAGE_ADDR_SIZE;
        match self.page_lookup(page_index) {
            None => {
                self.rtrace.insert(page_index, [0u8; PAGE_SIZE]);
                self.set_hash_trace(page_index, 0);
                0u32
            }
            Some(cached_page) => {
                let cached_page = cached_page.borrow();
                // lookup in page
                let page_addr = (addr as usize) & PAGE_ADDR_MASK;

                if let std::collections::btree_map::Entry::Vacant(e) = self.rtrace.entry(page_index)
                {
                    e.insert(cached_page.data);
                    self.set_hash_trace(page_index, 0);
                };

                u32::from_be_bytes(
                    (&cached_page.data[page_addr..page_addr + 4])
                        .try_into()
                        .unwrap(),
                )
            }
        }
    }

    pub fn byte(&mut self, addr: u32) -> u8 {
        let word = self.get_memory(addr & 0xFFFFFFFC);
        word.to_be_bytes()[(addr & 3) as usize]
    }

    fn alloc_page(&mut self, page_index: u32) -> Rc<RefCell<CachedPage>> {
        let cached_page = Rc::new(RefCell::new(CachedPage::new()));
        self.pages.insert(page_index, cached_page.clone());

        cached_page
    }

    pub fn set_memory(&mut self, addr: u32, v: u32) {
        // addr must be aligned to 4 bytes
        if addr & 0x3 != 0 {
            panic!("unaligned memory access: {:x?}", addr);
        }

        if addr as usize >= MAX_MEMORY {
            log::warn!("write out of memory: {:x?}", addr);
        }

        let page_index = addr >> PAGE_ADDR_SIZE;
        let page_addr = (addr as usize) & PAGE_ADDR_MASK;
        let cached_page = match self.page_lookup(page_index) {
            None => {
                // allocate the page if we have not already
                // Golang may mmap relatively large ranges, but we only allocate just in time.
                self.alloc_page(page_index)
            }
            Some(cached_page) => {
                // self.invalidate(addr);
                cached_page
            }
        };

        if let std::collections::btree_map::Entry::Vacant(e) = self.rtrace.entry(page_index) {
            e.insert(cached_page.borrow().data);
            self.set_hash_trace(page_index, 0);
        };

        self.wtrace[0].insert(page_index, cached_page.clone());

        let mut cached_page = cached_page.borrow_mut();
        cached_page.data[page_addr..page_addr + 4].copy_from_slice(&v.to_be_bytes());
    }

    pub fn usage(&self) -> String {
        let total = self.pages.len() * PAGE_SIZE;
        let unit = (1 << 10) as usize;
        if total < unit {
            return format!("{} B", total);
        }

        // KiB, MiB, GiB, TiB, ...
        let (mut div, mut exp) = (unit, 0usize);
        let mut n = total / div;
        while n >= unit {
            div *= unit;
            exp += 1;
            n /= unit;
        }
        let exp_table = b"KMGTPE";
        format!("{}, {}iB", total / div, exp_table[exp] as char)
    }

    pub fn read_memory_range(&mut self, addr: u32, count: u32) {
        self.addr = addr;
        self.count = count;
    }

    pub fn set_memory_range<'a>(
        &mut self,
        mut addr: u32,
        mut r: Box<dyn Read + 'a>,
    ) -> Result<(), std::io::ErrorKind> {
        loop {
            if addr as usize >= MAX_MEMORY {
                log::warn!("read out of memory: {:x?}", addr);
            }
            let page_index = addr >> PAGE_ADDR_SIZE;
            let page_addr = addr & (PAGE_ADDR_MASK as u32);
            let cached_page = self.page_lookup(page_index);
            let page = match cached_page {
                None => self.alloc_page(page_index),
                Some(page) => page,
            };

            if let std::collections::btree_map::Entry::Vacant(e) = self.rtrace.entry(page_index) {
                e.insert(page.borrow().data);
                self.set_hash_trace(page_index, 0);
            };

            self.wtrace[0].insert(page_index, page.clone());

            let mut page = page.borrow_mut();

            let n = r.read(&mut page.data[(page_addr as usize)..]).unwrap();
            if n == 0 {
                return Ok(());
            }
            addr += n as u32;
        }
    }

    fn alloc_hash_page(&mut self, page_index: u32, level: usize) -> Rc<RefCell<CachedPage>> {
        let cached_page = Rc::new(RefCell::new(CachedPage::new()));

        cached_page.borrow_mut().data[0..PAGE_SIZE].copy_from_slice(&CONST_HASH_PAGES[level]);

        self.pages.insert(page_index, cached_page.clone());

        cached_page
    }

    pub fn set_hash_range<'a>(
        &mut self,
        page_index: u32,
        page_hash: [u8; 32],
        level: usize,
    ) -> Result<(), std::io::ErrorKind> {
        let hash_addr = (page_index << 5) + MAX_MEMORY as u32;
        let page_index = hash_addr >> PAGE_ADDR_SIZE;
        let hash_offset = hash_addr as usize & PAGE_ADDR_MASK;
        let cached_page: Option<Rc<RefCell<CachedPage>>> = self.page_lookup(page_index);
        let page = match cached_page {
            None => self.alloc_hash_page(page_index, level),
            Some(page) => page,
        };

        log::trace!("{:X} hash : {:?}", hash_addr, page_hash);

        page.borrow_mut().data[hash_offset..hash_offset + 32].copy_from_slice(&page_hash);

        if level < 2 {
            self.wtrace[level + 1].insert(page_index, page.clone());
        }

        Ok(())
    }

    // return image id and page hash root
    pub fn update_page_hash(&mut self) {
        // MAIN MEMORY   0 .. 0x80000000
        for (page_index, cached_page) in self.wtrace[0].clone().iter() {
            let _ = self.set_hash_range(*page_index, hash_page(&cached_page.borrow().data), 0);
        }

        self.wtrace[0].clear();

        // L1 HASH PAGES  0x80000000.. 0x81000000
        for (page_index, cached_page) in self.wtrace[1].clone().iter() {
            let _ = self.set_hash_range(*page_index, hash_page(&cached_page.borrow().data), 1);
        }

        self.wtrace[1].clear();

        // L2 HASH PAGES  0x81000000.. 0x81020000
        for (page_index, cached_page) in self.wtrace[2].clone().iter() {
            let _ = self.set_hash_range(*page_index, hash_page(&cached_page.borrow().data), 2);
        }

        self.wtrace[2].clear();
    }

    pub fn compute_image_id(&mut self, pc: u32, regiters: &[u8; 39 * 4]) -> ([u8; 32], [u8; 32]) {
        // ROOT PAGES  0x81020000.. 0x81020400
        let root_page = 0x81020u32;
        let hash = match self.pages.get(&root_page) {
            None => {
                panic!("compute image ID fail")
            }
            Some(page) => {
                page.borrow_mut().data[REGISTERS_OFFSET..REGISTERS_OFFSET + 39 * 4]
                    .copy_from_slice(regiters);
                hash_page(&page.borrow().data)
            }
        };

        let mut final_data = [0u8; 36];

        for i in (0..32).step_by(WORD_SIZE) {
            let data = u32::from_le_bytes(hash[i..i + WORD_SIZE].try_into().unwrap());
            final_data[i..i + WORD_SIZE].copy_from_slice(&data.to_be_bytes());
        }
        final_data[32..].copy_from_slice(&pc.to_le_bytes());

        let image_id_u64s = poseidon(&final_data);
        let image_id = image_id_u64s
            .iter()
            .flat_map(|&num| num.to_le_bytes())
            .collect::<Vec<_>>();

        log::trace!("page root hash: {:?}", hash);
        log::trace!("end pc: {:?}", pc.to_le_bytes());
        log::trace!("image id: {:?}", image_id);

        (image_id.try_into().unwrap(), hash)
    }

    pub fn check_image_id(&mut self, pc: u32, image_id: [u8; 32]) {
        // MAIN MEMORY   0 .. 0x80000000
        for (page_index, cached_page) in self.pages.clone().iter() {
            if *page_index == 0x81020u32 {
                let root_page = 0x81020u32;
                let hash = match self.pages.get(&root_page) {
                    None => {
                        panic!("compute image ID fail")
                    }
                    Some(page) => hash_page(&page.borrow().data),
                };

                let mut final_data = [0u8; 36];
                final_data[0..4].copy_from_slice(&pc.to_be_bytes());
                final_data[4..36].copy_from_slice(&hash);

                let real_image_id_u64s = poseidon(&final_data);
                let real_image_id = real_image_id_u64s
                    .iter()
                    .flat_map(|&num| num.to_le_bytes())
                    .collect::<Vec<_>>();
                let real_image_id: [u8; 32] = real_image_id.try_into().unwrap();

                if image_id != real_image_id {
                    log::error!("image_id not match {:?} {:?}", image_id, real_image_id);
                }
            } else {
                let hash = hash_page(&cached_page.borrow().data);
                let hash_addr = (page_index << 5) + MAX_MEMORY as u32;
                let mut saved_hash = [0u8; 32];
                saved_hash[0..4].copy_from_slice(&self.get_memory(hash_addr).to_be_bytes());
                saved_hash[4..8].copy_from_slice(&self.get_memory(hash_addr + 4).to_be_bytes());
                saved_hash[8..12].copy_from_slice(&self.get_memory(hash_addr + 8).to_be_bytes());
                saved_hash[12..16].copy_from_slice(&self.get_memory(hash_addr + 12).to_be_bytes());
                saved_hash[16..20].copy_from_slice(&self.get_memory(hash_addr + 16).to_be_bytes());
                saved_hash[20..24].copy_from_slice(&self.get_memory(hash_addr + 20).to_be_bytes());
                saved_hash[24..28].copy_from_slice(&self.get_memory(hash_addr + 24).to_be_bytes());
                saved_hash[28..32].copy_from_slice(&self.get_memory(hash_addr + 28).to_be_bytes());

                if hash != saved_hash {
                    log::error!(
                        "{:X} hash not match {:?} {:?}",
                        page_index,
                        hash,
                        saved_hash
                    );
                }
            }
        }
    }

    pub fn get_input_image(&mut self) -> BTreeMap<u32, u32> {
        let mut image = BTreeMap::<u32, u32>::new();

        for (page_index, cached_page) in self.rtrace.iter() {
            let addr = page_index << 12;
            for i in 0..(PAGE_SIZE / 4) {
                let mut bytes = [0u8; 4];
                bytes.copy_from_slice(&cached_page[i << 2..(i << 2) + 4]);
                image.insert(addr + (i << 2) as u32, u32::from_le_bytes(bytes));
            }
        }

        self.rtrace.clear();
        image
    }

    pub fn get_total_image(&mut self) -> BTreeMap<u32, u32> {
        let mut image = BTreeMap::<u32, u32>::new();

        for (page_index, cached_page) in self.pages.iter() {
            let addr = page_index << 12;
            for i in 0..(PAGE_SIZE / 4) {
                let mut bytes = [0u8; 4];
                bytes.copy_from_slice(&cached_page.borrow().data[i << 2..(i << 2) + 4]);
                image.insert(addr + (i << 2) as u32, u32::from_le_bytes(bytes));
            }
        }

        self.rtrace.clear();
        image
    }
}

impl Read for Memory {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.count == 0 {
            return Ok(0usize);
        }

        let end_addr = self.addr + self.count;

        let page_index = self.addr >> PAGE_ADDR_SIZE;
        // todo: fix bug, read too much
        let (start, mut end) = (self.addr & (PAGE_ADDR_MASK as u32), PAGE_SIZE as u32);

        if page_index == (end_addr >> PAGE_ADDR_SIZE) {
            end = end_addr & (PAGE_ADDR_MASK as u32);
        }

        let cached_page: Option<Rc<RefCell<CachedPage>>> = self.page_lookup(page_index);
        let n = match cached_page {
            None => {
                let size = buf.len().min((end - start) as usize);
                for (_, element) in buf.iter_mut().enumerate().take(size) {
                    *element = 0;
                }
                size
            }
            Some(cached_page) => {
                let page = cached_page.borrow_mut();
                let size = buf.len().min((end - start) as usize);
                buf[0..size].copy_from_slice(&page.data[(start as usize)..(start as usize + size)]);
                size
            }
        };
        self.addr += n as u32;
        self.count -= n as u32;

        Ok(n)
    }
}
