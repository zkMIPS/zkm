# mips emulator

Supported 55 instructions:
```
'addi', 'addiu', 'addu', 'and', 'andi',
'b', 'beq', 'beqz', 'bgez', 'bgtz', 'blez', 'bltz', 'bne', 'bnez',
'clz', 'divu',
'j', 'jal', 'jalr', 'jr',
'lb', 'lbu', 'lui', 'lw', 'lwr',
'mfhi', 'mflo', 'move', 'movn', 'movz', 'mtlo', 'mul', 'multu',
'negu', 'nop', 'not', 'or', 'ori',
'sb', 'sll', 'sllv', 'slt', 'slti', 'sltiu', 'sltu', 'sra', 'srl', 'srlv', 'subu', 'sw', 'swr', 'sync', 'syscall',
'xor', 'xori'
```

This repository acts as a spec for `zkMIPS`, a tool for generating zero knowledge proof for any
MIPS program. Of course, the main purpose of `zkMIPS` is to prove the state transition of `EVM`.


For this repository, it is a MIPS emulator. It utilizes merkle tree to proof the memory integrity.

Here is the roadmap:

- [x] implement instruction interpreter, thoroughly tested.
- [ ] substitute `keccak256` in merkle tree to `poseidon`.

