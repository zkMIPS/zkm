//go:build mips
// +build mips

TEXT ·SyscallWrite(SB), $0-24
    MOVW $4004, R2 // #define SYS_write 4004
    MOVW fd+0(FP), R4
    MOVW write_buf+4(FP), R5
    MOVW nbytes+16(FP), R6
    SYSCALL
    MOVW R2, ret+0(FP)
    RET

TEXT ·SyscallHintLen(SB), $0-4
    MOVW $0xF0, R2 // #define SYS_hint_len 0xF0
    SYSCALL
    MOVW R2, ret+0(FP)
    RET

TEXT ·SyscallHintRead(SB), $0-16
    MOVW $0xF1, R2 // #define SYS_hint_read 0xF1
    MOVW ptr+0(FP), R4
    MOVW len+12(FP), R5
    SYSCALL
    RET
