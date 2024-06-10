#[allow(dead_code)]
#[derive(Debug)]
pub enum ProgramError {
    OutOfGas,
    InvalidRegister,
    InvalidSyscall,
    InvalidOpcode,
    Trap,
    StackUnderflow,
    InvalidRlp,
    InvalidJumpDestination,
    InvalidJumpiDestination,
    StackOverflow,
    KernelPanic,
    MemoryError(MemoryError),
    GasLimitError,
    InterpreterError,
    IntegerTooLarge,
    ProverInputError(ProverInputError),
    UnknownContractCode,
}

#[allow(clippy::enum_variant_names)]
#[derive(Debug)]
pub enum MemoryError {
    ContextTooLarge { context: u32 },
    SegmentTooLarge { segment: u32 },
    VirtTooLarge { virt: u32 },
}

#[derive(Debug)]
pub enum ProverInputError {
    OutOfMptData,
    OutOfRlpData,
    CodeHashNotFound,
    InvalidMptInput,
    InvalidInput,
    InvalidFunction,
}
