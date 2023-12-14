use std::ops::{Index, IndexMut, Range, RangeFrom};

/// Note: 2**12 = 4 KiB, the minimum page-size in Unicorn for mmap
pub const PAGE_ADDR_SIZE: usize = 12;
pub const PAGE_KEY_SIZE: usize = 32 - PAGE_ADDR_SIZE;
pub const PAGE_SIZE: usize = 1 << PAGE_ADDR_SIZE;
pub const PAGE_ADDR_MASK: usize = PAGE_SIZE - 1;
const MAX_PAGE_COUNT: usize = 1 << PAGE_KEY_SIZE;
const PAGE_KEY_MASK: usize = MAX_PAGE_COUNT - 1;
pub const MAX_MEMORY: usize = 0x80000000;
pub const HASH_LEVEL: usize = 3;

#[derive(Debug, Clone)]
pub struct Page([u8; PAGE_SIZE]);

impl Index<usize> for Page {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl IndexMut<usize> for Page {
    fn index_mut(&mut self, index: usize) -> &mut u8 {
        &mut self.0[index]
    }
}

impl Index<Range<usize>> for Page {
    type Output = [u8];

    fn index(&self, index: Range<usize>) -> &[u8] {
        &self.0[index]
    }
}

impl Index<RangeFrom<usize>> for Page {
    type Output = [u8];

    fn index(&self, index: RangeFrom<usize>) -> &Self::Output {
        &self.0[index]
    }
}

impl IndexMut<Range<usize>> for Page {
    fn index_mut(&mut self, index: Range<usize>) -> &mut [u8] {
        &mut self.0[index]
    }
}

impl IndexMut<RangeFrom<usize>> for Page {
    fn index_mut(&mut self, index: RangeFrom<usize>) -> &mut [u8] {
        &mut self.0[index]
    }
}

impl Page {
    fn new() -> Page {
        Page([0; PAGE_SIZE])
    }

    pub fn get_data(&self) -> &[u8; PAGE_SIZE] {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct CachedPage {
    pub data: Page,
}

impl CachedPage {
    pub fn new() -> Self {
        Self { data: Page::new() }
    }
}
