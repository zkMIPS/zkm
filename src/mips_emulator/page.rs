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
pub struct CachedPage {
    pub data: [u8; PAGE_SIZE],
}

impl Default for CachedPage {
    fn default() -> Self {
        Self::new()
    }
}

impl CachedPage {
    pub fn new() -> Self {
        Self {
            data: [0u8; PAGE_SIZE],
        }
    }
}
