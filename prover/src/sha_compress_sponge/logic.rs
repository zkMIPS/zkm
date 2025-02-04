pub(crate) fn sha_ch(a: u32, b: u32, c: u32) -> u32 {
    (a & b) ^ (!a & c)
}

pub(crate) fn sha_ma(a: u32, b: u32, c: u32) -> u32 {
    (a & b) ^ (a & c) ^ (b & c)
}

pub(crate) fn sha_sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

pub(crate) fn sha_sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}
