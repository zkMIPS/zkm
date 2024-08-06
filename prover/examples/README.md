# Examples

## Prove the Golang code 

* Compile the Go code to MIPS

Write your own hello.go, and compile with

```
GOOS=linux GOARCH=mips GOMIPS=softfloat go build hello.go
```

* Split the ELF hello into segments. Note that the flag `BLOCK_NO` is only necessary for minigeth.

```
BASEDIR=./emulator/test-vectors RUST_LOG=info ELF_PATH=./emulator/test-vectors/minigeth BLOCK_NO=13284491 SEG_OUTPUT=/tmp/output SEG_SIZE=1024 ARGS="" \
    cargo run --release --example zkmips split

OR

RUST_LOG=info ELF_PATH=./emulator/test-vectors/hello  SEG_OUTPUT=/tmp/output SEG_SIZE=1024 ARGS="" \
    cargo run --release --example zkmips split_without_preimage
```

* Generate proof for each segment

```
BASEDIR=./emulator/test-vectors RUST_LOG=info BLOCK_NO=13284491 SEG_FILE="/tmp/output/0" SEG_SIZE=1024 \
    cargo run --release --example zkmips prove
```

* Aggregate proof

```
BASEDIR=./emulator/test-vectors RUST_LOG=info BLOCK_NO=13284491 SEG_FILE="/tmp/output/0" SEG_FILE2="/tmp/output/1" SEG_SIZE=1024 \
    cargo run --release --example zkmips aggregate_proof
```

* Aggregate proof all

```
BASEDIR=./emulator/test-vectors RUST_LOG=info BLOCK_NO=13284491 SEG_FILE_DIR="/tmp/output" SEG_FILE_NUM=299 SEG_SIZE=1024 \
    cargo run --release --example zkmips aggregate_proof_all
```

## Prove the Rust code 

* Download and install toolchain for mips

```
wget http://musl.cc/mips-linux-muslsf-cross.tgz
tar -zxvf mips-linux-muslsf-cross.tgz
```

* Modify ~/.cargo/config:

```
[target.mips-unknown-linux-musl]
linker = "<path-to>/mips-linux-muslsf-cross/bin/mips-linux-muslsf-gcc"
rustflags = ["--cfg", 'target_os="zkvm"',"-C", "target-feature=+crt-static", "-C", "link-arg=-g"]
```

* Build the Sha2/Revme

```
cd prover/examples/sha2
cargo build --target=mips-unknown-linux-musl
```

* Run the host program

// echo -n 'world!' | sha256sum
// 711e9609339e92b03ddc0a211827dba421f38f9ed8b9d806e1ffdd8c15ffa03d

```
cd ../..
ARGS="711e9609339e92b03ddc0a211827dba421f38f9ed8b9d806e1ffdd8c15ffa03d world!" RUST_LOG=info ELF_PATH=examples/sha2/target/mips-unknown-linux-musl/debug/sha2-bench SEG_OUTPUT=/tmp/output cargo run --release --example zkmips bench

Or

RUST_LOG=info ELF_PATH=examples/revme/target/mips-unknown-linux-musl/debug/evm JSON_PATH=../emulator/test-vectors/test.json SEG_OUTPUT=/tmp/output cargo run --release --example zkmips revm
```
