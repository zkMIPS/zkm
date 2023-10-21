use crate::cpu::generation::MipsTrace;
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Kernel {
    pub(crate) code: Vec<u8>,
}

