#![no_std]
#![no_main]

zkm_runtime::entrypoint!(main);

pub fn main() {
    let result = zkm_runtime::io::read::<u32>();
    let n = zkm_runtime::io::read::<u32>();

    let mut a: u128 = 0;
    let mut b: u128 = 1;
    let mut sum: u128;
    for _ in 0..n {
        sum = a + b;
        a = b;
        b = sum;
    }

    assert!(b as u32 == result);
    zkm_runtime::io::commit(&(b as u32));
}
