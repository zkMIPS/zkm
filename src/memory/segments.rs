/// Use segment for possible register reduce optimization
#[allow(dead_code)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Debug)]
pub enum Segment {
    /// Code
    Code = 0,
    /// Main memory, owned by the contract code.
    MainMemory = 1,
    /// General purpose kernel memory, used by various kernel functions.
    /// In general, calling a helper function can result in this memory being clobbered.
    KernelGeneral = 2,
    /// Another segment for general purpose kernel use.
    KernelGeneral2 = 3,
    /// instructions; initialised by `kernel/asm/shift.asm::init_shift_table()`.
    ShiftTable = 4,
}

impl Segment {
    pub(crate) const COUNT: usize = 5;

    pub(crate) fn all() -> [Self; Self::COUNT] {
        [
            Self::Code,
            Self::MainMemory,
            Self::KernelGeneral,
            Self::KernelGeneral2,
            Self::ShiftTable,
        ]
    }

    /// The variable name that gets passed into kernel assembly code.
    pub(crate) fn var_name(&self) -> &'static str {
        match self {
            Segment::Code => "SEGMENT_CODE",
            Segment::MainMemory => "SEGMENT_MAIN_MEMORY",
            Segment::KernelGeneral => "SEGMENT_KERNEL_GENERAL",
            Segment::KernelGeneral2 => "SEGMENT_KERNEL_GENERAL_2",
            Segment::ShiftTable => "SEGMENT_SHIFT_TABLE",
        }
    }

    #[allow(dead_code)]
    pub(crate) fn bit_range(&self) -> usize {
        match self {
            Segment::Code => 8,
            Segment::MainMemory => 8,
            Segment::KernelGeneral => 256,
            Segment::KernelGeneral2 => 256,
            Segment::ShiftTable => 256,
        }
    }
}
