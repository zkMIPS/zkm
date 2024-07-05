# Examples

## MIPS tools

* Compile the Go code to MIPS

Write your own hello.go, and compile with

```
GOOS=linux GOARCH=mips GOMIPS=softfloat go build hello.go
```

* Split the ELF hello into segments. Note that the flag `BLOCK_NO` is only necessary for minigeth.

```
BASEDIR=test-vectors RUST_LOG=info ELF_PATH=test-vectors/hello BLOCK_NO=13284491 SEG_OUTPUT=/tmp/output SEG_SIZE=1024 ARGS="" \
    cargo run --release --example zkmips split
```

* Generate proof for each segment

```
BASEDIR=test-vectors RUST_LOG=info BLOCK_NO=13284491 SEG_FILE="/tmp/output/0" SEG_SIZE=1024 \
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

- run bench

  - download/install toolchain for mips

    ```
    wget http://musl.cc/mips-linux-muslsf-cross.tgz
    tar -zxvf mips-linux-muslsf-cross.tgz
    ```

  - modify ~/.cargo/config:

    ```
    [target.mips-unknown-linux-musl]
    linker = <path-to>/mips-linux-muslsf-gcc"
    rustflags = ["--cfg", 'target_os="zkvm"',"-C", "target-feature=+crt-static", "-C", "link-arg=-g"]
    ```

  - build sha2

    ```
    cd examples/sha2
    cargo build --target=mips-unknown-linux-musl
    cd ../../
    ```

  - run bench

    ```
    RUST_LOG=info ELF_PATH=examples/sha2/target/mips-unknown-linux-musl/debug/sha2-bench SEG_OUTPUT=/tmp/output cargo run --release --example zkmips bench
    ```

Basically, you can run the example on a 32G RAM machine, if you get OOM error, please read https://github.com/zkMIPS/zkm/issues/97.

