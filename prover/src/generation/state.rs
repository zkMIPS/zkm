// use keccak_hash::keccak;
use crate::cpu::kernel::assembler::Kernel;
use crate::witness::errors::ProgramError;
use crate::witness::memory::MemoryState;
use crate::witness::state::RegistersState;
use crate::witness::traces::{TraceCheckpoint, Traces};
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use sha2::{Digest, Sha256};
use std::{cell::RefCell, rc::Rc};

pub const ZERO: [u8; 32] = [0u8; 32];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Receipt<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    pub proof: ProofWithPublicInputs<F, C, D>,
    pub root_before: Vec<u8>,
    pub userdata: Vec<u8>,
}

impl<F, C, const D: usize> Receipt<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub fn claim_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();

        hasher.update(self.root_before.clone());
        hasher.update(self.userdata.clone());
        let digest: [u8; 32] = hasher.finalize().into();
        digest
    }
}

pub(crate) struct GenerationStateCheckpoint {
    pub(crate) registers: RegistersState,
    pub(crate) traces: TraceCheckpoint,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Assumption {
    pub claim: [u8; 32],
    pub control_root: [u8; 32],
}

#[derive(Clone, Debug)]
pub enum AssumptionReceipt<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
{
    // A [Receipt] for a proven assumption.
    Proven(Box<Receipt<F, C, D>>),

    // An [Assumption] that is not directly proven to be true.
    Unresolved(Assumption),
}

impl<F, C, const D: usize> AssumptionReceipt<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    /// Returns the digest of the claim for this [AssumptionReceipt].
    pub fn claim_digest(&self) -> [u8; 32] {
        match self {
            Self::Proven(receipt) => receipt.claim_digest(),
            Self::Unresolved(assumption) => assumption.claim,
        }
    }
}

/// Container for assumptions in the executor environment.
pub type AssumptionReceipts<F, C, const D: usize> = Vec<AssumptionReceipt<F, C, D>>;
pub type AssumptionUsage<F, C, const D: usize> = Vec<(Assumption, AssumptionReceipt<F, C, D>)>;

impl<F, C, const D: usize> From<Receipt<F, C, D>> for AssumptionReceipt<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    /// Create a proven assumption from a [Receipt].
    fn from(receipt: Receipt<F, C, D>) -> Self {
        Self::Proven(Box::new(receipt))
    }
}

impl<F, C, const D: usize> From<Assumption> for AssumptionReceipt<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    /// Create an unresolved assumption from an [Assumption].
    fn from(assumption: Assumption) -> Self {
        Self::Unresolved(assumption)
    }
}

#[derive(Clone)]
pub(crate) struct GenerationState<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    pub(crate) registers: RegistersState,
    pub(crate) memory: MemoryState,
    pub(crate) input_stream: Vec<Vec<u8>>,
    pub(crate) input_stream_ptr: usize,
    pub(crate) public_values_stream: Vec<u8>,
    pub(crate) public_values_stream_ptr: usize,
    pub(crate) traces: Traces<F>,
    pub(crate) assumptions: Rc<RefCell<AssumptionReceipts<F, C, D>>>,
    pub(crate) assumptions_used: Rc<RefCell<AssumptionUsage<F, C, D>>>,
    pub(crate) step: usize,
}

impl<F, C, const D: usize> GenerationState<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub(crate) fn new(step: usize, kernel: &Kernel) -> Result<Self, ProgramError> {
        Ok(GenerationState {
            registers: RegistersState::new(kernel),
            memory: MemoryState::new(&[]), // FIXME
            traces: Traces::default(),
            input_stream: kernel.program.input_stream.clone(),
            input_stream_ptr: kernel.program.input_stream_ptr,
            public_values_stream: kernel.program.public_values_stream.clone(),
            public_values_stream_ptr: kernel.program.public_values_stream_ptr,
            assumptions: Rc::new(RefCell::new(Vec::new())),
            assumptions_used: Rc::new(RefCell::new(Vec::new())),
            step,
        })
    }

    pub fn add_assumption(
        &mut self,
        assumption: impl Into<AssumptionReceipt<F, C, D>>,
    ) -> &mut Self {
        let receipt: AssumptionReceipt<F, C, D> = assumption.into();
        log::info!("add assumption {:?}", receipt.claim_digest());
        self.assumptions.borrow_mut().push(receipt);
        self
    }

    pub(crate) fn find_assumption(
        &self,
        claim_digest: &[u8; 32],
        control_root: &[u8; 32],
    ) -> Option<(Assumption, AssumptionReceipt<F, C, D>)> {
        for assumption_receipt in self.assumptions.borrow().iter() {
            let cached_claim_digest = assumption_receipt.claim_digest();

            if cached_claim_digest != *claim_digest {
                log::debug!(
                    "receipt with claim {:?} does not match",
                    cached_claim_digest
                );
                continue;
            }

            return Some((
                Assumption {
                    claim: *claim_digest,
                    control_root: *control_root,
                },
                assumption_receipt.clone(),
            ));
        }

        None
    }

    pub fn checkpoint(&self) -> GenerationStateCheckpoint {
        GenerationStateCheckpoint {
            registers: self.registers,
            traces: self.traces.checkpoint(),
        }
    }

    pub fn rollback(&mut self, checkpoint: GenerationStateCheckpoint) {
        self.registers = checkpoint.registers;
        self.traces.rollback(checkpoint.traces);
    }

    /// Updates `program_counter`, and potentially adds some extra handling if we're jumping to a
    /// special location.
    pub fn jump_to(&mut self, dst: usize) {
        self.registers.program_counter = self.registers.next_pc;
        self.registers.next_pc = dst;
    }
}
