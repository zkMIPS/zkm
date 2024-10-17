#!/bin/bash
FEAT=
if [ X"$#" != X"0" ]; then
  export USE_GPU_PROVE=1
  FEAT='--features gpu,cuda'
fi
echo "$FEAT"

BASEDIR=../emulator/test-vectors RUST_LOG=info BLOCK_NO=13284491 SEG_FILE_DIR="/tmp/output" SEG_START_ID=0 SEG_NUM=1 SEG_SIZE=262144 \
    cargo run $FEAT --release --example zkmips prove_segments
