#!/bin/bash
FEAT=
CONF=

if [ X"$#" != X"0" ]; then
  FEAT='--features gpu,cuda'
  CONF='--config ../config.toml'
fi
echo "$FEAT"
echo "$CONF"

BASEDIR=../emulator/test-vectors RUST_LOG=info ELF_PATH=../emulator/test-vectors/minigeth BLOCK_NO=13284491 SEG_OUTPUT=/tmp/output SEG_SIZE=262144 ARGS="1" \
    cargo run $FEAT $CONF --release --example zkmips split
