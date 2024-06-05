use crate::all_stark::{AllStark, Table, NUM_TABLES};
use crate::config::StarkConfig;
use crate::constraint_consumer::ConstraintConsumer;

use crate::cross_table_lookup::{
    num_ctl_helper_columns_by_table, verify_cross_table_lookups, CtlCheckVars,
    GrandProductChallenge, GrandProductChallengeSet,
};
use crate::evaluation_frame::StarkEvaluationFrame;
use crate::lookup::LookupCheckVars;

use crate::memory::VALUE_LIMBS;
use crate::proof::PublicValues;
use anyhow::{ensure, Result};
use itertools::Itertools;
use plonky2::field::extension::{Extendable, FieldExtension};
use plonky2::field::types::Field;
use plonky2::fri::verifier::verify_fri_proof;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::plonk_common::reduce_with_powers;
use std::any::type_name;

use crate::proof::{
    AllProof, AllProofChallenges, StarkOpeningSet, StarkProof, StarkProofChallenges,
};
use crate::stark::Stark;
use crate::vanishing_poly::eval_vanishing_poly;

pub fn verify_proof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    all_stark: &AllStark<F, D>,
    all_proof: AllProof<F, C, D>,
    config: &StarkConfig,
) -> Result<()>
where
{
    let AllProofChallenges {
        stark_challenges,
        ctl_challenges,
    } = all_proof
        .get_challenges(config)
        .map_err(|_| anyhow::Error::msg("Invalid sampling of proof challenges."))?;

    let num_lookup_columns = all_stark.num_lookups_helper_columns(config);

    let AllStark {
        arithmetic_stark,
        cpu_stark,
        poseidon_stark,
        poseidon_sponge_stark,
        logic_stark,
        memory_stark,
        cross_table_lookups,
    } = all_stark;

    let num_ctl_helper_cols = num_ctl_helper_columns_by_table(
        cross_table_lookups,
        all_stark.arithmetic_stark.constraint_degree(),
    );

    let ctl_vars_per_table = CtlCheckVars::from_proofs(
        &all_proof.stark_proofs,
        cross_table_lookups,
        &ctl_challenges,
        &num_lookup_columns,
        &num_ctl_helper_cols,
    );

    verify_stark_proof_with_challenges(
        arithmetic_stark,
        &all_proof.stark_proofs[Table::Arithmetic as usize].proof,
        &stark_challenges[Table::Arithmetic as usize],
        &ctl_vars_per_table[Table::Arithmetic as usize],
        &ctl_challenges,
        config,
    )?;

    verify_stark_proof_with_challenges(
        cpu_stark,
        &all_proof.stark_proofs[Table::Cpu as usize].proof,
        &stark_challenges[Table::Cpu as usize],
        &ctl_vars_per_table[Table::Cpu as usize],
        &ctl_challenges,
        config,
    )?;
    verify_stark_proof_with_challenges(
        poseidon_stark,
        &all_proof.stark_proofs[Table::Poseidon as usize].proof,
        &stark_challenges[Table::Poseidon as usize],
        &ctl_vars_per_table[Table::Poseidon as usize],
        &ctl_challenges,
        config,
    )?;
    verify_stark_proof_with_challenges(
        poseidon_sponge_stark,
        &all_proof.stark_proofs[Table::PoseidonSponge as usize].proof,
        &stark_challenges[Table::PoseidonSponge as usize],
        &ctl_vars_per_table[Table::PoseidonSponge as usize],
        &ctl_challenges,
        config,
    )?;
    verify_stark_proof_with_challenges(
        logic_stark,
        &all_proof.stark_proofs[Table::Logic as usize].proof,
        &stark_challenges[Table::Logic as usize],
        &ctl_vars_per_table[Table::Logic as usize],
        &ctl_challenges,
        config,
    )?;
    verify_stark_proof_with_challenges(
        memory_stark,
        &all_proof.stark_proofs[Table::Memory as usize].proof,
        &stark_challenges[Table::Memory as usize],
        &ctl_vars_per_table[Table::Memory as usize],
        &ctl_challenges,
        config,
    )?;

    let public_values = all_proof.public_values;

    // Extra sums to add to the looked last value.
    // Only necessary for the Memory values.
    let mut extra_looking_sums = vec![vec![F::ZERO; config.num_challenges]; NUM_TABLES];

    // Memory
    extra_looking_sums[Table::Memory as usize] = (0..config.num_challenges)
        .map(|i| get_memory_extra_looking_sum(&public_values, ctl_challenges.challenges[i]))
        .collect_vec();

    verify_cross_table_lookups::<F, D>(
        cross_table_lookups,
        all_proof
            .stark_proofs
            .map(|p| p.proof.openings.ctl_zs_first),
        extra_looking_sums,
        config,
    )
}

/// Computes the extra product to multiply to the looked value. It contains memory operations not in the CPU trace:
/// - trie roots writes before kernel bootstrapping.
pub(crate) fn get_memory_extra_looking_sum<F, const D: usize>(
    _public_values: &PublicValues,
    _challenge: GrandProductChallenge<F>,
) -> F
where
    F: RichField + Extendable<D>,
{
    /*
    // Add metadata and state root writes. Skip due to not enabling
    let fields = [
        (
            GlobalMetadata::StateTrieRootDigestBefore,
            public_values.roots_before.root,
        ),
        (
            GlobalMetadata::StateTrieRootDigestAfter,
            public_values.roots_after.root,
        ),
    ];

    let segment = F::from_canonical_u32(Segment::GlobalMetadata as u32);

    fields.map(|(field, val)| prod = add_data_write(challenge, segment, prod, field as usize, val));
    */

    F::ZERO
}

fn add_data_write<F, const D: usize>(
    challenge: GrandProductChallenge<F>,
    segment: F,
    running_sum: F,
    index: usize,
    val: u32,
) -> F
where
    F: RichField + Extendable<D>,
{
    let mut row = [F::ZERO; 13];
    row[0] = F::ZERO; // is_read
    row[1] = F::ZERO; // context
    row[2] = segment;
    row[3] = F::from_canonical_usize(index);

    for j in 0..VALUE_LIMBS {
        row[j + 4] = F::from_canonical_u32(val >> (j * 32));
    }
    row[5] = F::ONE; // timestamp
    running_sum * challenge.combine(row.iter())
}

pub(crate) fn verify_stark_proof_with_challenges<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    S: Stark<F, D>,
    const D: usize,
>(
    stark: &S,
    proof: &StarkProof<F, C, D>,
    challenges: &StarkProofChallenges<F, D>,
    ctl_vars: &[CtlCheckVars<F, F::Extension, F::Extension, D>],
    ctl_challenges: &GrandProductChallengeSet<F>,
    config: &StarkConfig,
) -> Result<()> {
    log::debug!("Checking proof: {}", type_name::<S>());
    let num_ctl_polys = ctl_vars
        .iter()
        .map(|ctl| ctl.helper_columns.len())
        .sum::<usize>();
    let num_ctl_z_polys = ctl_vars.len();
    validate_proof_shape(stark, proof, config, num_ctl_polys, num_ctl_z_polys)?;

    let StarkOpeningSet {
        local_values,
        next_values,
        auxiliary_polys,
        auxiliary_polys_next,
        ctl_zs_first: _,
        quotient_polys,
    } = &proof.openings;
    let vars = S::EvaluationFrame::from_values(local_values, next_values);

    let degree_bits = proof.recover_degree_bits(config);
    let (l_0, l_last) = eval_l_0_and_l_last(degree_bits, challenges.stark_zeta);
    let last = F::primitive_root_of_unity(degree_bits).inverse();
    let z_last = challenges.stark_zeta - last.into();
    let mut consumer = ConstraintConsumer::<F::Extension>::new(
        challenges
            .stark_alphas
            .iter()
            .map(|&alpha| F::Extension::from_basefield(alpha))
            .collect::<Vec<_>>(),
        z_last,
        l_0,
        l_last,
    );
    let num_lookup_columns = stark.num_lookup_helper_columns(config);
    let lookup_challenges = (num_lookup_columns > 0).then(|| {
        ctl_challenges
            .challenges
            .iter()
            .map(|ch| ch.beta)
            .collect::<Vec<_>>()
    });

    let lookup_vars = stark.uses_lookups().then(|| LookupCheckVars {
        local_values: auxiliary_polys[..num_lookup_columns].to_vec(),
        next_values: auxiliary_polys_next[..num_lookup_columns].to_vec(),
        challenges: lookup_challenges.unwrap(),
    });
    let lookups = stark.lookups();
    eval_vanishing_poly::<F, F::Extension, F::Extension, S, D, D>(
        stark,
        &vars,
        &lookups,
        lookup_vars,
        ctl_vars,
        &mut consumer,
    );
    let vanishing_polys_zeta = consumer.accumulators();

    // Check each polynomial identity, of the form `vanishing(x) = Z_H(x) quotient(x)`, at zeta.
    let zeta_pow_deg = challenges.stark_zeta.exp_power_of_2(degree_bits);
    let z_h_zeta = zeta_pow_deg - F::Extension::ONE;
    // `quotient_polys_zeta` holds `num_challenges * quotient_degree_factor` evaluations.
    // Each chunk of `quotient_degree_factor` holds the evaluations of `t_0(zeta),...,t_{quotient_degree_factor-1}(zeta)`
    // where the "real" quotient polynomial is `t(X) = t_0(X) + t_1(X)*X^n + t_2(X)*X^{2n} + ...`.
    // So to reconstruct `t(zeta)` we can compute `reduce_with_powers(chunk, zeta^n)` for each
    // `quotient_degree_factor`-sized chunk of the original evaluations.
    for (i, chunk) in quotient_polys
        .chunks(stark.quotient_degree_factor())
        .enumerate()
    {
        ensure!(
            vanishing_polys_zeta[i] == z_h_zeta * reduce_with_powers(chunk, zeta_pow_deg),
            "Mismatch between evaluation and opening of quotient polynomial"
        );
    }

    let merkle_caps = vec![
        proof.trace_cap.clone(),
        proof.auxiliary_polys_cap.clone(),
        proof.quotient_polys_cap.clone(),
    ];

    let num_ctl_zs = ctl_vars
        .iter()
        .map(|ctl| ctl.helper_columns.len())
        .collect::<Vec<_>>();
    verify_fri_proof::<F, C, D>(
        &stark.fri_instance(
            challenges.stark_zeta,
            F::primitive_root_of_unity(degree_bits),
            num_ctl_polys,
            num_ctl_zs,
            config,
        ),
        &proof.openings.to_fri_openings(),
        &challenges.fri_challenges,
        &merkle_caps,
        &proof.opening_proof,
        &config.fri_params(degree_bits),
    )?;

    Ok(())
}

fn validate_proof_shape<F, C, S, const D: usize>(
    stark: &S,
    proof: &StarkProof<F, C, D>,
    config: &StarkConfig,
    num_ctl_helpers: usize,
    num_ctl_zs: usize,
) -> anyhow::Result<()>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    S: Stark<F, D>,
{
    let StarkProof {
        trace_cap,
        auxiliary_polys_cap,
        quotient_polys_cap,
        openings,
        // The shape of the opening proof will be checked in the FRI verifier (see
        // validate_fri_proof_shape), so we ignore it here.
        opening_proof: _,
    } = proof;

    let StarkOpeningSet {
        local_values,
        next_values,
        auxiliary_polys,
        auxiliary_polys_next,
        ctl_zs_first,
        quotient_polys,
    } = openings;

    let degree_bits = proof.recover_degree_bits(config);
    let fri_params = config.fri_params(degree_bits);
    let cap_height = fri_params.config.cap_height;
    let num_auxiliary = num_ctl_helpers + stark.num_lookup_helper_columns(config) + num_ctl_zs;

    ensure!(trace_cap.height() == cap_height);
    ensure!(auxiliary_polys_cap.height() == cap_height);
    ensure!(quotient_polys_cap.height() == cap_height);

    ensure!(local_values.len() == S::COLUMNS);
    ensure!(next_values.len() == S::COLUMNS);
    ensure!(auxiliary_polys.len() == num_auxiliary);
    ensure!(auxiliary_polys_next.len() == num_auxiliary);
    ensure!(ctl_zs_first.len() == num_ctl_zs);
    ensure!(quotient_polys.len() == stark.num_quotient_polys(config));

    Ok(())
}

/// Evaluate the Lagrange polynomials `L_0` and `L_(n-1)` at a point `x`.
/// `L_0(x) = (x^n - 1)/(n * (x - 1))`
/// `L_(n-1)(x) = (x^n - 1)/(n * (g * x - 1))`, with `g` the first element of the subgroup.
fn eval_l_0_and_l_last<F: Field>(log_n: usize, x: F) -> (F, F) {
    let n = F::from_canonical_usize(1 << log_n);
    let g = F::primitive_root_of_unity(log_n);
    let z_x = x.exp_power_of_2(log_n) - F::ONE;
    let invs = F::batch_multiplicative_inverse(&[n * (x - F::ONE), n * (g * x - F::ONE)]);

    (z_x * invs[0], z_x * invs[1])
}

#[cfg(test)]
pub(crate) mod testutils {
    use super::*;

    /// Output all the extra memory rows that don't appear in the CPU trace but are
    /// necessary to correctly check the MemoryStark CTL.
    pub(crate) fn get_memory_extra_looking_values<F, const D: usize>(
        _public_values: &PublicValues,
    ) -> Vec<Vec<F>>
    where
        F: RichField + Extendable<D>,
    {
        /*
        let fields = [{}];
        fields.map(|(field, val)| {
            extra_looking_rows.push(add_extra_looking_row(segment, field as usize, val))
        });
        */
        Vec::new()
    }

    fn add_extra_looking_row<F, const D: usize>(segment: F, index: usize, val: u32) -> Vec<F>
    where
        F: RichField + Extendable<D>,
    {
        let mut row = vec![F::ZERO; 13];
        row[0] = F::ZERO; // is_read
        row[1] = F::ZERO; // context
        row[2] = segment;
        row[3] = F::from_canonical_usize(index);

        row[4] = F::from_canonical_u32(val);
        // FIXME
        row[12] = F::ONE; // timestamp
        row
    }
}

#[cfg(test)]
mod tests {
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::polynomial::PolynomialValues;
    use plonky2::field::types::Sample;

    use crate::verifier::eval_l_0_and_l_last;

    #[test]
    fn test_eval_l_0_and_l_last() {
        type F = GoldilocksField;
        let log_n = 5;
        let n = 1 << log_n;

        let x = F::rand(); // challenge point
        let expected_l_first_x = PolynomialValues::selector(n, 0).ifft().eval(x);
        let expected_l_last_x = PolynomialValues::selector(n, n - 1).ifft().eval(x);

        let (l_first_x, l_last_x) = eval_l_0_and_l_last(log_n, x);
        assert_eq!(l_first_x, expected_l_first_x);
        assert_eq!(l_last_x, expected_l_last_x);
    }
}
