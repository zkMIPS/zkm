# Examples

## Prove the Golang code 

* Compile the Go code to MIPS

Write your own hello.go, and compile with

```
GOOS=linux GOARCH=mips GOMIPS=softfloat go build hello.go
```

* Split the ELF hello into segments. Note that the flag `BLOCK_NO` is only necessary for minigeth.

```
cd prover/examples/split-seg

BASEDIR=../../../emulator/test-vectors RUST_LOG=info ELF_PATH=../../../emulator/test-vectors/minigeth BLOCK_NO=13284491 SEG_OUTPUT=/tmp/output SEG_SIZE=65536 ARGS="" cargo run --release
```

* Generate proof for specific segment (Set SEG_START_ID to specific segment id and set SEG_NUM to 1)

```
cd ../prove-seg
BASEDIR=../../../emulator/test-vectors RUST_LOG=info BLOCK_NO=13284491 SEG_FILE_DIR="/tmp/output" SEG_START_ID=0 SEG_NUM=1 SEG_SIZE=65536 \
    cargo run --release
```

* Aggregate proof all segments (Set SEG_START_ID to 0, and set SEG_NUM to the total segments number)

```
BASEDIR=../../../emulator/test-vectors RUST_LOG=info BLOCK_NO=13284491 SEG_FILE_DIR="/tmp/output" SEG_START_ID=0 SEG_NUM=299 SEG_SIZE=65536 \
    cargo run --release
```

### Prove Go sdk code
The SDK provide Read and Commit interface to read input and commit output.
Take sha2-go for example:

* Build the sha2-go

```
cd prover/examples/sha2-go/guest
GOOS=linux GOARCH=mips GOMIPS=softfloat go build .
```
* Run the host program 

```
cd ../host
ARGS="711e9609339e92b03ddc0a211827dba421f38f9ed8b9d806e1ffdd8c15ffa03d world!" RUST_LOG=info SEG_OUTPUT=/tmp/output cargo run --release
```

## Prove the Rust code 

* Download and install toolchain for mips-zkm-zkvm-elf

```
curl --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/zkMIPS/toolchain/refs/heads/main/setup.sh | sh
```

* Build and run Sha2/revme (**new**)

```
cd prover/examples/sha2-rust/host

# echo -n 'world!' | sha256sum
# 711e9609339e92b03ddc0a211827dba421f38f9ed8b9d806e1ffdd8c15ffa03d

ARGS="711e9609339e92b03ddc0a211827dba421f38f9ed8b9d806e1ffdd8c15ffa03d world!" RUST_LOG=info SEG_OUTPUT=/tmp/output cargo run --release

Or

cd prover/examples/revme/host

RUST_LOG=info JSON_PATH=../../../../emulator/test-vectors/test.json SEG_OUTPUT=/tmp/output SEG_SIZE=262144 cargo run --release

```

## Prove precompile code
* Build the sha2-rust (**new**)
```
cd prover/examples/sha2-rust/host
cargo check
```

* Build and run the sha2-precompile (**new**)
```
cd ../../sha2-precompile/host
RUST_LOG=info PRECOMPILE_PATH=../../sha2-rust/guest/elf/mips-zkm-zkvm-elf SEG_OUTPUT=/tmp/output cargo run --release
```
