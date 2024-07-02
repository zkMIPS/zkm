# Examples

## MIPS tools

* Compile the Go code to MIPS

Write your own hello.go, and compile with

```
GOOS=linux GOARCH=mips GOMIPS=softfloat go build hello.go
```

* Split the ELF hello into segments. Note that the flag `BLOCK_NO` is only necessary for minigeth.

```
BASEDIR=test-vectors RUST_LOG=info ELF_PATH=test-vectors/hello BLOCK_NO=13284491 SEG_OUTPUT=/tmp/output SEG_SIZE=65536 ARGS="" \
    cargo run --release --example zkmips split
```

* Generate proof for each segment

```
BASEDIR=test-vectors RUST_LOG=info BLOCK_NO=13284491 SEG_FILE="/tmp/output/0" SEG_SIZE=65536 \
    cargo run --release --example zkmips prove
```

* Aggregate proof

```
BASEDIR=test-vectors RUST_LOG=info BLOCK_NO=13284491 SEG_FILE="/tmp/output/0" SEG_FILE2="/tmp/output/1" SEG_SIZE=1024 \
    cargo run --release --example zkmips aggregate_proof
```

* Aggregate proof all

```
BASEDIR=test-vectors RUST_LOG=info BLOCK_NO=13284491 SEG_FILE_DIR="/tmp/output" SEG_FILE_NUM=299 SEG_SIZE=1024 \
    cargo run --release --example zkmips aggregate_proof_all
```

Basically, you can run the example on a 32G RAM machine, if you get OOM error, please read https://github.com/zkMIPS/zkm/issues/97.
