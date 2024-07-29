# powdr-revme

## Setup

1. Install `mips-linux-muslsf-cross`

```
mkdir /mnt/data
wget http://musl.cc/mips-linux-muslsf-cross.tgz
tar -zxvf mips-linux-muslsf-cross.tgz -C /mnt/data
```

2. Setup MIPS target

Edit `~/.cargo/config` and add:

```
[target.mips-unknown-linux-musl]
linker = "/mnt/data/mips-linux-muslsf-cross/bin/mips-linux-muslsf-gcc"
rustflags = ["-C", "target-feature=+crt-static", "-C", "link-arg=-g", "-C", "link-args=-lc"]
```

## Compile and Prove
```
git clone https://github.com/zkMIPS/revme
cd revme
cargo build -Z build-std=core,alloc --target mips-unknown-linux-musl
```
Then you can get the MIPS ELF `target/mips-unknown-linux-musl/debug/evm`, then we can refer to [test_execution_rust_fib](https://github.com/zkMIPS/zkm/blob/cd579f799d2a556a625c5052e3722d8c83cf9ef0/src/mips_emulator/tests.rs#L77) and [test_execution_minigeth](https://github.com/zkMIPS/zkm/blob/cd579f799d2a556a625c5052e3722d8c83cf9ef0/src/mips_emulator/tests.rs#L98) to generate the segments and prove them.
