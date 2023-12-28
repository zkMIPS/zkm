# Examples

## MIPS tools

* Compile the Go code to MIPS

Write your own hello.go, and compile with

```
export GOOS=linux
export GOARCH=mips
export GOMIPS=softfloat
go build hello.go
```

* Split the ELF hello into segments

```
BASEDIR=test-vectors RUST_LOG=trace ELF_PATH=test-vectors/hello BLOCK_NO=13284491 SEG_OUTPUT=/tmp/output SEG_SIZE=1024 \
    cargo run --release --example zkmips split
```

* Generate proof for each segment

```
BASEDIR=test-vectors RUST_LOG=trace BLOCK_NO=13284491 BLOCK_FILE="" SEG_FILE="/tmp/output0" \
    cargo run --release --example zkmips prove
```


