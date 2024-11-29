#!/bin/bash
FEAT=
CONF=

if [ X"$#" != X"0" ]; then
  FEAT='--features gpu,cuda'
  CONF='--config ../config.toml'
fi
echo "$FEAT"
echo "$CONF"

BASEDIR=../emulator/test-vectors RUST_LOG=info BLOCK_NO=13284491 SEG_FILE_DIR="/tmp/output" SEG_START_ID=0 SEG_NUM=1 SEG_SIZE=262144 \
    cargo run $FEAT $CONF --release --example zkmips prove_segments
