#!/bin/bash
FEAT=
if [ X"$#" != X"0" ]; then
  #export USE_GPU_PROVE=1
  FEAT='--features gpu,cuda'
fi
echo "$FEAT"

BASEDIR=../emulator/test-vectors RUST_LOG=info ELF_PATH=../emulator/test-vectors/minigeth BLOCK_NO=13284491 SEG_OUTPUT=/tmp/output SEG_SIZE=262144 ARGS="" \
    cargo run $FEAT --release --example zkmips split
