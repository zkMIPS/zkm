/// Use segment for possible register reduce optimization
#[allow(dead_code)]
#[derive(Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Debug)]
pub enum Segment {
    /// Code
    Code = 0,
    /// General purpose kernel memory, used by various kernel functions.
    /// In general, calling a helper function can result in this memory being clobbered.
    KernelGeneral = 1,
    /// Another segment for general purpose kernel use.
    KernelGeneral2 = 2,
    /// instructions; initialised by `kernel/asm/shift.asm::init_shift_table()`.
    ShiftTable = 3,
    // Register file
    RegisterFile = 4,
    // Global Meta
    GlobalMetadata = 5,
}

impl Segment {
    pub(crate) const COUNT: usize = 6;

    pub(crate) fn all() -> [Self; Self::COUNT] {
        [
            Self::Code,
            Self::KernelGeneral,
            Self::KernelGeneral2,
            Self::ShiftTable,
            Self::RegisterFile,
            Self::GlobalMetadata,
        ]
    }

    /// The variable name that gets passed into kernel assembly code.
    pub(crate) fn var_name(&self) -> &'static str {
        match self {
            Segment::Code => "SEGMENT_CODE",
            Segment::KernelGeneral => "SEGMENT_KERNEL_GENERAL",
            Segment::KernelGeneral2 => "SEGMENT_KERNEL_GENERAL_2",
            Segment::ShiftTable => "SEGMENT_SHIFT_TABLE",
            Segment::RegisterFile => "SEGMENT_REGISTERFILE_TABLE",
            Segment::GlobalMetadata => "SEGMENT_GLOBAL_METADATA",
        }
    }

    #[allow(dead_code)]
    pub(crate) fn bit_range(&self) -> usize {
        match self {
            Segment::Code => 32,
            Segment::KernelGeneral => 256,
            Segment::KernelGeneral2 => 256,
            Segment::ShiftTable => 32,
            Segment::RegisterFile => 32,
            Segment::GlobalMetadata => 32,
        }
    }
}
