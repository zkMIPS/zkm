use crate::all_stark::NUM_PUBLIC_INPUT_USERDATA;
use itertools::Itertools;
use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::fri::oracle::PolynomialBatch;
use plonky2::fri::proof::{FriChallenges, FriChallengesTarget, FriProof, FriProofTarget};
use plonky2::fri::structure::{
    FriOpeningBatch, FriOpeningBatchTarget, FriOpenings, FriOpeningsTarget,
};
use plonky2::hash::hash_types::{MerkleCapTarget, RichField};
use plonky2::hash::merkle_tree::MerkleCap;
use plonky2::iop::ext_target::ExtensionTarget;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::{GenericConfig, Hasher};
use plonky2::util::serialization::{Buffer, IoResult, Read, Write};
use plonky2_maybe_rayon::*;
use serde::{Deserialize, Serialize};

use crate::all_stark::NUM_TABLES;
use crate::config::StarkConfig;
use crate::cross_table_lookup::GrandProductChallengeSet;

/// A STARK proof for each table, plus some metadata used to create recursive wrapper proofs.
#[derive(Debug, Clone)]
pub struct AllProof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    pub stark_proofs: [StarkProofWithMetadata<F, C, D>; NUM_TABLES],
    pub(crate) ctl_challenges: GrandProductChallengeSet<F>,
    pub public_values: PublicValues,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> AllProof<F, C, D> {
    pub fn degree_bits(&self, config: &StarkConfig) -> [usize; NUM_TABLES] {
        core::array::from_fn(|i| self.stark_proofs[i].proof.recover_degree_bits(config))
    }
}

pub(crate) struct AllProofChallenges<F: RichField + Extendable<D>, const D: usize> {
    pub stark_challenges: [StarkProofChallenges<F, D>; NUM_TABLES],
    pub ctl_challenges: GrandProductChallengeSet<F>,
}

#[allow(unused)] // TODO: should be used soon
pub(crate) struct AllChallengerState<F: RichField + Extendable<D>, H: Hasher<F>, const D: usize> {
    /// Sponge state of the challenger before starting each proof,
    /// along with the final state after all proofs are done. This final state isn't strictly needed.
    pub states: [H::Permutation; NUM_TABLES + 1],
    pub ctl_challenges: GrandProductChallengeSet<F>,
}

/// Memory values which are public.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PublicValues {
    pub roots_before: MemRoots,
    pub roots_after: MemRoots,
    pub userdata: Vec<u8>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemRoots {
    pub root: [u32; 8],
}

/// Memory values which are public.
/// Note: All the larger integers are encoded with 32-bit limbs in little-endian order.
#[derive(Eq, PartialEq, Debug)]
pub struct PublicValuesTarget {
    pub roots_before: MemRootsTarget,
    pub roots_after: MemRootsTarget,
    pub userdata: [Target; NUM_PUBLIC_INPUT_USERDATA],
}

impl PublicValuesTarget {
    pub fn to_buffer(&self, buffer: &mut Vec<u8>) -> IoResult<()> {
        let MemRootsTarget {
            root: state_root_before,
        } = self.roots_before;

        buffer.write_target_array(&state_root_before)?;

        let MemRootsTarget {
            root: state_root_after,
        } = self.roots_after;

        buffer.write_target_array(&state_root_after)?;

        buffer.write_target_array(&self.userdata)?;
        Ok(())
    }

    pub fn from_buffer(buffer: &mut Buffer) -> IoResult<Self> {
        let roots_before = MemRootsTarget {
            root: buffer.read_target_array()?,
        };

        let roots_after = MemRootsTarget {
            root: buffer.read_target_array()?,
        };

        let userdata = buffer.read_target_array()?;

        Ok(Self {
            roots_before,
            roots_after,
            userdata,
        })
    }

    pub fn from_public_inputs(pis: &[Target]) -> Self {
        Self {
            roots_before: MemRootsTarget::from_public_inputs(&pis[0..8]),
            roots_after: MemRootsTarget::from_public_inputs(&pis[8..16]),
            userdata: pis[16..16 + NUM_PUBLIC_INPUT_USERDATA].try_into().unwrap(),
        }
    }

    pub fn select<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        condition: BoolTarget,
        pv0: Self,
        pv1: Self,
    ) -> Self {
        Self {
            roots_before: MemRootsTarget::select(
                builder,
                condition,
                pv0.roots_before,
                pv1.roots_before,
            ),
            roots_after: MemRootsTarget::select(
                builder,
                condition,
                pv0.roots_after,
                pv1.roots_after,
            ),
            userdata: core::array::from_fn(|i| {
                builder.select(condition, pv0.userdata[i], pv1.userdata[i])
            }),
        }
    }
}

#[derive(Eq, PartialEq, Debug, Copy, Clone)]
pub struct MemRootsTarget {
    pub root: [Target; 8],
}

impl MemRootsTarget {
    pub const SIZE: usize = 24;

    pub fn from_public_inputs(pis: &[Target]) -> Self {
        let root = pis[0..8].try_into().unwrap();
        Self { root }
    }

    pub fn select<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        condition: BoolTarget,
        tr0: Self,
        tr1: Self,
    ) -> Self {
        Self {
            root: core::array::from_fn(|i| builder.select(condition, tr0.root[i], tr1.root[i])),
        }
    }

    pub fn connect<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        tr0: Self,
        tr1: Self,
    ) {
        for i in 0..8 {
            builder.connect(tr0.root[i], tr1.root[i]);
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StarkProof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    /// Merkle cap of LDEs of trace values.
    pub trace_cap: MerkleCap<F, C::Hasher>,
    /// Merkle cap of LDEs of lookup helper and CTL columns.
    pub auxiliary_polys_cap: MerkleCap<F, C::Hasher>,
    /// Merkle cap of LDEs of quotient polynomial evaluations.
    pub quotient_polys_cap: MerkleCap<F, C::Hasher>,
    /// Purported values of each polynomial at the challenge point.
    pub openings: StarkOpeningSet<F, D>,
    /// A batch FRI argument for all openings.
    pub opening_proof: FriProof<F, C::Hasher, D>,
}

/// A `StarkProof` along with some metadata about the initial Fiat-Shamir state, which is used when
/// creating a recursive wrapper proof around a STARK proof.
#[derive(Debug, Clone)]
pub struct StarkProofWithMetadata<F, C, const D: usize>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    pub(crate) init_challenger_state: <C::Hasher as Hasher<F>>::Permutation,
    pub proof: StarkProof<F, C, D>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> StarkProof<F, C, D> {
    /// Recover the length of the trace from a STARK proof and a STARK config.
    pub fn recover_degree_bits(&self, config: &StarkConfig) -> usize {
        let initial_merkle_proof = &self.opening_proof.query_round_proofs[0]
            .initial_trees_proof
            .evals_proofs[0]
            .1;
        let lde_bits = config.fri_config.cap_height + initial_merkle_proof.siblings.len();
        lde_bits - config.fri_config.rate_bits
    }

    pub fn num_ctl_zs(&self) -> usize {
        self.openings.ctl_zs_first.len()
    }
}

#[derive(Eq, PartialEq, Debug)]
pub struct StarkProofTarget<const D: usize> {
    pub trace_cap: MerkleCapTarget,
    pub auxiliary_polys_cap: MerkleCapTarget,
    pub quotient_polys_cap: MerkleCapTarget,
    pub openings: StarkOpeningSetTarget<D>,
    pub opening_proof: FriProofTarget<D>,
}

impl<const D: usize> StarkProofTarget<D> {
    pub fn to_buffer(&self, buffer: &mut Vec<u8>) -> IoResult<()> {
        buffer.write_target_merkle_cap(&self.trace_cap)?;
        buffer.write_target_merkle_cap(&self.auxiliary_polys_cap)?;
        buffer.write_target_merkle_cap(&self.quotient_polys_cap)?;
        buffer.write_target_fri_proof(&self.opening_proof)?;
        self.openings.to_buffer(buffer)?;
        Ok(())
    }

    pub fn from_buffer(buffer: &mut Buffer) -> IoResult<Self> {
        let trace_cap = buffer.read_target_merkle_cap()?;
        let auxiliary_polys_cap = buffer.read_target_merkle_cap()?;
        let quotient_polys_cap = buffer.read_target_merkle_cap()?;
        let opening_proof = buffer.read_target_fri_proof()?;
        let openings = StarkOpeningSetTarget::from_buffer(buffer)?;

        Ok(Self {
            trace_cap,
            auxiliary_polys_cap,
            quotient_polys_cap,
            openings,
            opening_proof,
        })
    }

    /// Recover the length of the trace from a STARK proof and a STARK config.
    pub fn recover_degree_bits(&self, config: &StarkConfig) -> usize {
        let initial_merkle_proof = &self.opening_proof.query_round_proofs[0]
            .initial_trees_proof
            .evals_proofs[0]
            .1;
        let lde_bits = config.fri_config.cap_height + initial_merkle_proof.siblings.len();
        lde_bits - config.fri_config.rate_bits
    }
}

pub(crate) struct StarkProofChallenges<F: RichField + Extendable<D>, const D: usize> {
    /// Random values used to combine STARK constraints.
    pub stark_alphas: Vec<F>,

    /// Point at which the STARK polynomials are opened.
    pub stark_zeta: F::Extension,

    pub fri_challenges: FriChallenges<F, D>,
}

pub(crate) struct StarkProofChallengesTarget<const D: usize> {
    pub stark_alphas: Vec<Target>,
    pub stark_zeta: ExtensionTarget<D>,
    pub fri_challenges: FriChallengesTarget<D>,
}

/// Purported values of each polynomial at the challenge point.
#[derive(Debug, Clone, Serialize)]
pub struct StarkOpeningSet<F: RichField + Extendable<D>, const D: usize> {
    /// Openings of trace polynomials at `zeta`.
    pub local_values: Vec<F::Extension>,
    /// Openings of trace polynomials at `g * zeta`.
    pub next_values: Vec<F::Extension>,
    /// Openings of lookups and cross-table lookups `Z` polynomials at `zeta`.
    pub auxiliary_polys: Vec<F::Extension>,
    /// Openings of lookups and cross-table lookups `Z` polynomials at `g * zeta`.
    pub auxiliary_polys_next: Vec<F::Extension>,
    /// Openings of cross-table lookups `Z` polynomials at `1`.
    pub ctl_zs_first: Vec<F>,
    /// Openings of quotient polynomials at `zeta`.
    pub quotient_polys: Vec<F::Extension>,
}

impl<F: RichField + Extendable<D>, const D: usize> StarkOpeningSet<F, D> {
    pub fn new<C: GenericConfig<D, F = F>>(
        zeta: F::Extension,
        g: F,
        trace_commitment: &PolynomialBatch<F, C, D>,
        auxiliary_polys_commitment: &PolynomialBatch<F, C, D>,
        quotient_commitment: &PolynomialBatch<F, C, D>,
        num_lookup_columns: usize,
        num_ctl_polys: &[usize],
    ) -> Self {
        let total_num_helper_cols: usize = num_ctl_polys.iter().sum();

        let eval_commitment = |z: F::Extension, c: &PolynomialBatch<F, C, D>| {
            c.polynomials
                .par_iter()
                .map(|p| p.to_extension().eval(z))
                .collect::<Vec<_>>()
        };
        let eval_commitment_base = |z: F, c: &PolynomialBatch<F, C, D>| {
            c.polynomials
                .par_iter()
                .map(|p| p.eval(z))
                .collect::<Vec<_>>()
        };

        let auxiliary_first = eval_commitment_base(F::ONE, auxiliary_polys_commitment);
        let ctl_zs_first = auxiliary_first[num_lookup_columns + total_num_helper_cols..].to_vec();
        let zeta_next = zeta.scalar_mul(g);
        Self {
            local_values: eval_commitment(zeta, trace_commitment),
            next_values: eval_commitment(zeta_next, trace_commitment),
            auxiliary_polys: eval_commitment(zeta, auxiliary_polys_commitment),
            auxiliary_polys_next: eval_commitment(zeta_next, auxiliary_polys_commitment),
            ctl_zs_first,
            quotient_polys: eval_commitment(zeta, quotient_commitment),
        }
    }

    pub(crate) fn to_fri_openings(&self) -> FriOpenings<F, D> {
        let zeta_batch = FriOpeningBatch {
            values: self
                .local_values
                .iter()
                .chain(&self.auxiliary_polys)
                .chain(&self.quotient_polys)
                .copied()
                .collect_vec(),
        };
        let zeta_next_batch = FriOpeningBatch {
            values: self
                .next_values
                .iter()
                .chain(&self.auxiliary_polys_next)
                .copied()
                .collect_vec(),
        };
        debug_assert!(!self.ctl_zs_first.is_empty());
        let ctl_first_batch = FriOpeningBatch {
            values: self
                .ctl_zs_first
                .iter()
                .copied()
                .map(F::Extension::from_basefield)
                .collect(),
        };

        FriOpenings {
            batches: vec![zeta_batch, zeta_next_batch, ctl_first_batch],
        }
    }
}

#[derive(Eq, PartialEq, Debug)]
pub struct StarkOpeningSetTarget<const D: usize> {
    pub local_values: Vec<ExtensionTarget<D>>,
    pub next_values: Vec<ExtensionTarget<D>>,
    pub auxiliary_polys: Vec<ExtensionTarget<D>>,
    pub auxiliary_polys_next: Vec<ExtensionTarget<D>>,
    pub ctl_zs_first: Vec<Target>,
    pub quotient_polys: Vec<ExtensionTarget<D>>,
}

impl<const D: usize> StarkOpeningSetTarget<D> {
    pub fn to_buffer(&self, buffer: &mut Vec<u8>) -> IoResult<()> {
        buffer.write_target_ext_vec(&self.local_values)?;
        buffer.write_target_ext_vec(&self.next_values)?;
        buffer.write_target_ext_vec(&self.auxiliary_polys)?;
        buffer.write_target_ext_vec(&self.auxiliary_polys_next)?;
        buffer.write_target_vec(&self.ctl_zs_first)?;
        buffer.write_target_ext_vec(&self.quotient_polys)?;
        Ok(())
    }

    pub fn from_buffer(buffer: &mut Buffer) -> IoResult<Self> {
        let local_values = buffer.read_target_ext_vec::<D>()?;
        let next_values = buffer.read_target_ext_vec::<D>()?;
        let auxiliary_polys = buffer.read_target_ext_vec::<D>()?;
        let auxiliary_polys_next = buffer.read_target_ext_vec::<D>()?;
        let ctl_zs_first = buffer.read_target_vec()?;
        let quotient_polys = buffer.read_target_ext_vec::<D>()?;

        Ok(Self {
            local_values,
            next_values,
            auxiliary_polys,
            auxiliary_polys_next,
            ctl_zs_first,
            quotient_polys,
        })
    }

    pub(crate) fn to_fri_openings(&self, zero: Target) -> FriOpeningsTarget<D> {
        let zeta_batch = FriOpeningBatchTarget {
            values: self
                .local_values
                .iter()
                .chain(&self.auxiliary_polys)
                .chain(&self.quotient_polys)
                .copied()
                .collect_vec(),
        };
        let zeta_next_batch = FriOpeningBatchTarget {
            values: self
                .next_values
                .iter()
                .chain(&self.auxiliary_polys_next)
                .copied()
                .collect_vec(),
        };
        debug_assert!(!self.ctl_zs_first.is_empty());
        let ctl_first_batch = FriOpeningBatchTarget {
            values: self
                .ctl_zs_first
                .iter()
                .copied()
                .map(|t| t.to_ext_target(zero))
                .collect(),
        };

        FriOpeningsTarget {
            batches: vec![zeta_batch, zeta_next_batch, ctl_first_batch],
        }
    }
}

pub struct StarkProofWithPublicInputsTarget<const D: usize> {
    pub proof: StarkProofTarget<D>,
    pub public_inputs: Vec<Target>,
}

#[derive(Debug, Clone)]
pub struct StarkProofWithPublicInputs<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    pub proof: StarkProof<F, C, D>,
    // TODO: Maybe make it generic over a `S: Stark` and replace with `[F; S::PUBLIC_INPUTS]`.
    pub public_inputs: Vec<F>,
}
