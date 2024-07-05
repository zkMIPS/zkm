use plonky2::field::extension::Extendable;
use plonky2::fri::proof::{FriProof, FriProofTarget};
use plonky2::hash::hash_types::RichField;
use plonky2::iop::challenger::{Challenger, RecursiveChallenger};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};

use crate::all_stark::{AllStark, NUM_TABLES};
use crate::config::StarkConfig;
use crate::cross_table_lookup::get_grand_product_challenge_set;
use crate::proof::*;
use crate::witness::errors::ProgramError;

fn observe_root<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    challenger: &mut Challenger<F, C::Hasher>,
    root: &[u32; 8],
) {
    for limb in root.iter() {
        challenger.observe_element(F::from_canonical_u32(*limb));
    }
}

fn observe_trie_roots<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    challenger: &mut Challenger<F, C::Hasher>,
    trie_roots: &MemRoots,
) {
    observe_root::<F, C, D>(challenger, &trie_roots.root);
}

fn observe_trie_roots_target<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    challenger: &mut RecursiveChallenger<F, C::Hasher, D>,
    trie_roots: &MemRootsTarget,
) where
    C::Hasher: AlgebraicHasher<F>,
{
    challenger.observe_elements(&trie_roots.root);
}

/*
fn observe_extra_block_data<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    challenger: &mut Challenger<F, C::Hasher>,
    extra_data: &ExtraBlockData,
) -> Result<(), ProgramError> {
    challenger.observe_elements(&h256_limbs(extra_data.genesis_state_trie_root));
    challenger.observe_element(u256_to_u32(extra_data.txn_number_before)?);
    challenger.observe_element(u256_to_u32(extra_data.txn_number_after)?);
    let gas_used_before = u256_to_u64(extra_data.gas_used_before)?;
    challenger.observe_element(gas_used_before.0);
    challenger.observe_element(gas_used_before.1);
    let gas_used_after = u256_to_u64(extra_data.gas_used_after)?;
    challenger.observe_element(gas_used_after.0);
    challenger.observe_element(gas_used_after.1);
    for i in 0..8 {
        challenger.observe_elements(&u256_limbs(extra_data.block_bloom_before[i]));
    }
    for i in 0..8 {
        challenger.observe_elements(&u256_limbs(extra_data.block_bloom_after[i]));
    }

    Ok(())
}

fn observe_extra_block_data_target<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    challenger: &mut RecursiveChallenger<F, C::Hasher, D>,
    extra_data: &ExtraBlockDataTarget,
) where
    C::Hasher: AlgebraicHasher<F>,
{
    challenger.observe_elements(&extra_data.genesis_state_trie_root);
    challenger.observe_element(extra_data.txn_number_before);
    challenger.observe_element(extra_data.txn_number_after);
    challenger.observe_elements(&extra_data.gas_used_before);
    challenger.observe_elements(&extra_data.gas_used_after);
    challenger.observe_elements(&extra_data.block_bloom_before);
    challenger.observe_elements(&extra_data.block_bloom_after);
}
*/

pub(crate) fn observe_public_values<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    challenger: &mut Challenger<F, C::Hasher>,
    public_values: &PublicValues,
) -> Result<(), ProgramError> {
    observe_trie_roots::<F, C, D>(challenger, &public_values.roots_before);
    observe_trie_roots::<F, C, D>(challenger, &public_values.roots_after);
    for elem in &public_values.userdata {
        challenger.observe_element(F::from_canonical_u8(*elem));
    }
    Ok(())
}

pub(crate) fn observe_public_values_target<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    challenger: &mut RecursiveChallenger<F, C::Hasher, D>,
    public_values: &PublicValuesTarget,
) where
    C::Hasher: AlgebraicHasher<F>,
{
    observe_trie_roots_target::<F, C, D>(challenger, &public_values.roots_before);
    observe_trie_roots_target::<F, C, D>(challenger, &public_values.roots_after);
    challenger.observe_elements(&public_values.userdata);
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> AllProof<F, C, D> {
    /// Computes all Fiat-Shamir challenges used in the STARK proof.
    pub(crate) fn get_challenges(
        &self,
        config: &StarkConfig,
    ) -> Result<AllProofChallenges<F, D>, ProgramError> {
        let mut challenger = Challenger::<F, C::Hasher>::new();

        for proof in &self.stark_proofs {
            challenger.observe_cap(&proof.proof.trace_cap);
        }

        observe_public_values::<F, C, D>(&mut challenger, &self.public_values)?;

        let ctl_challenges =
            get_grand_product_challenge_set(&mut challenger, config.num_challenges);

        Ok(AllProofChallenges {
            stark_challenges: core::array::from_fn(|i| {
                challenger.compact();
                self.stark_proofs[i]
                    .proof
                    .get_challenges(&mut challenger, config)
            }),
            ctl_challenges,
        })
    }

    #[allow(unused)] // TODO: should be used soon
    pub(crate) fn get_challenger_states(
        &self,
        all_stark: &AllStark<F, D>,
        config: &StarkConfig,
    ) -> AllChallengerState<F, C::Hasher, D> {
        let mut challenger = Challenger::<F, C::Hasher>::new();

        for proof in &self.stark_proofs {
            challenger.observe_cap(&proof.proof.trace_cap);
        }

        observe_public_values::<F, C, D>(&mut challenger, &self.public_values);

        let ctl_challenges =
            get_grand_product_challenge_set(&mut challenger, config.num_challenges);

        let lookups = all_stark.num_lookups_helper_columns(config);

        let mut challenger_states = vec![challenger.compact()];
        for i in 0..NUM_TABLES {
            self.stark_proofs[i]
                .proof
                .get_challenges(&mut challenger, config);
            challenger_states.push(challenger.compact());
        }

        AllChallengerState {
            states: challenger_states.try_into().unwrap(),
            ctl_challenges,
        }
    }
}

impl<F, C, const D: usize> StarkProof<F, C, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    /// Computes all Fiat-Shamir challenges used in the STARK proof.
    pub(crate) fn get_challenges(
        &self,
        challenger: &mut Challenger<F, C::Hasher>,
        config: &StarkConfig,
    ) -> StarkProofChallenges<F, D> {
        let degree_bits = self.recover_degree_bits(config);

        let StarkProof {
            auxiliary_polys_cap,
            quotient_polys_cap,
            openings,
            opening_proof:
                FriProof {
                    commit_phase_merkle_caps,
                    final_poly,
                    pow_witness,
                    ..
                },
            ..
        } = &self;

        let num_challenges = config.num_challenges;

        challenger.observe_cap(auxiliary_polys_cap);

        let stark_alphas = challenger.get_n_challenges(num_challenges);

        challenger.observe_cap(quotient_polys_cap);
        let stark_zeta = challenger.get_extension_challenge::<D>();

        challenger.observe_openings(&openings.to_fri_openings());

        StarkProofChallenges {
            stark_alphas,
            stark_zeta,
            fri_challenges: challenger.fri_challenges::<C, D>(
                commit_phase_merkle_caps,
                final_poly,
                *pow_witness,
                degree_bits,
                &config.fri_config,
            ),
        }
    }
}

impl<const D: usize> StarkProofTarget<D> {
    pub(crate) fn get_challenges<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        challenger: &mut RecursiveChallenger<F, C::Hasher, D>,
        config: &StarkConfig,
    ) -> StarkProofChallengesTarget<D>
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        let StarkProofTarget {
            auxiliary_polys_cap: auxiliary_polys,
            quotient_polys_cap,
            openings,
            opening_proof:
                FriProofTarget {
                    commit_phase_merkle_caps,
                    final_poly,
                    pow_witness,
                    ..
                },
            ..
        } = &self;

        let num_challenges = config.num_challenges;

        challenger.observe_cap(auxiliary_polys);

        let stark_alphas = challenger.get_n_challenges(builder, num_challenges);

        challenger.observe_cap(quotient_polys_cap);
        let stark_zeta = challenger.get_extension_challenge(builder);

        challenger.observe_openings(&openings.to_fri_openings(builder.zero()));

        StarkProofChallengesTarget {
            stark_alphas,
            stark_zeta,
            fri_challenges: challenger.fri_challenges(
                builder,
                commit_phase_merkle_caps,
                final_poly,
                *pow_witness,
                &config.fri_config,
            ),
        }
    }
}
