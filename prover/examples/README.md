

# Examples

## Prove the Golang code 

* Compile the Go code to MIPS

Write your own hello.go, and compile with

```
GOOS=linux GOARCH=mips GOMIPS=softfloat go build hello.go
```

* Split the ELF hello into segments. Note that the flag `BLOCK_NO` is only necessary for minigeth.

```
BASEDIR=./emulator/test-vectors RUST_LOG=info ELF_PATH=./emulator/test-vectors/minigeth BLOCK_NO=13284491 SEG_OUTPUT=/tmp/output SEG_SIZE=65536 ARGS="" \
    cargo run --release --example zkmips split
```

* Generate proof for specific segment (Set SEG_START_ID to specific segment id and set SEG_NUM to 1)

```
BASEDIR=./emulator/test-vectors RUST_LOG=info BLOCK_NO=13284491 SEG_FILE_DIR="/tmp/output" SEG_START_ID=0 SEG_NUM=1 SEG_SIZE=65536 \
    cargo run --release --example zkmips prove_segments
```

* Aggregate proof all segments (Set SEG_START_ID to 0, and set SEG_NUM to the total segments number)

```
BASEDIR=./emulator/test-vectors RUST_LOG=info BLOCK_NO=13284491 SEG_FILE_DIR="/tmp/output" SEG_START_ID=0 SEG_NUM=299 SEG_SIZE=65536 \
    cargo run --release --example zkmips prove_segments
```

### Prove Go sdk code
The SDK provide Read and Commit interface to read input and commit output.
Take add-go for example:

* Build the add-go

```
cd prover/examples/add-go
GOOS=linux GOARCH=mips GOMIPS=softfloat go build .
cd ../../
```
* Run the host program 

```
RUST_LOG=info ELF_PATH=examples/add-go/go-add HOST_PROGRAM=add_example SEG_OUTPUT=/tmp/output SEG_SIZE=262144 cargo run --release --example zkmips prove_host_program
```

## Prove the Rust code 

**Note**: the "mips-linux-muslsf-cross" supports Linux only. If your are using a MacOS, please refer to [#147](https://github.com/zkMIPS/zkm/issues/147). 

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

* Build and run Sha2/revme (**new**)

```
cd prover/examples/sha2-rust/script

# echo -n 'world!' | sha256sum
# 711e9609339e92b03ddc0a211827dba421f38f9ed8b9d806e1ffdd8c15ffa03d

ARGS="711e9609339e92b03ddc0a211827dba421f38f9ed8b9d806e1ffdd8c15ffa03d world!" RUST_LOG=info SEG_OUTPUT=/tmp/output cargo run --release

Or

RUST_LOG=info JSON_PATH=../emulator/test-vectors/test.json SEG_OUTPUT=/tmp/output SEG_SIZE=262144 cargo run --release

```

Or build and run separately

- build the sha2/revme program

```
cd prover/examples/sha2-rust/script
cargo check
```

* Run the sha2/revme host program

```
# echo -n 'world!' | sha256sum
# 711e9609339e92b03ddc0a211827dba421f38f9ed8b9d806e1ffdd8c15ffa03d

cd ../../../

ARGS="711e9609339e92b03ddc0a211827dba421f38f9ed8b9d806e1ffdd8c15ffa03d world!" RUST_LOG=info ELF_PATH=examples/sha2-rust/program/elf/mips-unknown-linux-musl HOST_PROGRAM=sha2_rust SEG_OUTPUT=/tmp/output cargo run --release --example zkmips prove_host_program

Or

cd ../../../

RUST_LOG=info ELF_PATH=examples/revme/program/elf/mips-unknown-linux-musl HOST_PROGRAM=revm JSON_PATH=../emulator/test-vectors/test.json SEG_OUTPUT=/tmp/output SEG_SIZE=262144 cargo run --release --example zkmips prove_host_program
```

## Prove precompile code
* Build the sha2-rust (**new**)
```
cd prover/examples/sha2-rust/script
cargo check
```

* Build and run the sha2-precompile (**new**)
```
cd prover/examples/sha2-precompile/script
RUST_LOG=info PRECOMPILE_PATH=../../sha2-rust/program/elf/mips-unknown-linux-musl SEG_OUTPUT=/tmp/output cargo run --release
```

Or build/run sha2-precompile separately

```
cd ../../sha2-precompile/script
cargo check

cd ../../../

RUST_LOG=info PRECOMPILE_PATH=examples/sha2-rust/program/elf/mips-unknown-linux-musl ELF_PATH=examples/sha2-precompile/program/elf/mips-unknown-linux-musl HOST_PROGRAM=sha2_precompile SEG_OUTPUT=/tmp/output cargo run --release --example zkmips prove_host_program
```
