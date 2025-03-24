use std::any::type_name;

use anyhow::{ensure, Result};
use itertools::Itertools;
use plonky2::field::extension::Extendable;
use plonky2::field::packable::Packable;
use plonky2::field::packed::PackedField;
use plonky2::field::polynomial::{PolynomialCoeffs, PolynomialValues};
use plonky2::field::types::Field;
use plonky2::field::zero_poly_coset::ZeroPolyOnCoset;
use plonky2::fri::oracle::PolynomialBatch;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::challenger::Challenger;
use plonky2::plonk::config::GenericConfig;
use plonky2::timed;
use plonky2::util::timing::TimingTree;
use plonky2::util::transpose;
use plonky2_maybe_rayon::*;
use plonky2_util::{log2_ceil, log2_strict};

use crate::all_stark::{AllStark, Table, NUM_TABLES};
use crate::config::StarkConfig;
use crate::constraint_consumer::ConstraintConsumer;
use crate::cpu::kernel::assembler::Kernel;
use crate::cross_table_lookup::{
    cross_table_lookup_data, get_grand_product_challenge_set, CtlCheckVars, CtlData,
    GrandProductChallengeSet,
};
use crate::evaluation_frame::StarkEvaluationFrame;
use crate::generation::outputs::GenerationOutputs;
use crate::generation::state::{AssumptionReceipts, AssumptionUsage};
use crate::generation::{generate_traces, generate_traces_with_assumptions};
use crate::get_challenges::observe_public_values;
use crate::lookup::{lookup_helper_columns, Lookup, LookupCheckVars};
use crate::proof::{AllProof, PublicValues, StarkOpeningSet, StarkProof, StarkProofWithMetadata};
use crate::stark::Stark;
use crate::vanishing_poly::eval_vanishing_poly;
use std::{cell::RefCell, rc::Rc};

#[cfg(any(feature = "test", test))]
use crate::cross_table_lookup::testutils::check_ctls;

/// Generate traces, then create all STARK proofs.
pub fn prove<F, C, const D: usize>(
    all_stark: &AllStark<F, D>,
    kernel: &Kernel,
    config: &StarkConfig,
    timing: &mut TimingTree,
) -> Result<AllProof<F, C, D>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F=F>,
{
    let (proof, _outputs) = prove_with_outputs(all_stark, kernel, config, timing)?;
    Ok(proof)
}

pub fn prove_with_assumptions<F, C, const D: usize>(
    all_stark: &AllStark<F, D>,
    kernel: &Kernel,
    config: &StarkConfig,
    timing: &mut TimingTree,
    assumptions: AssumptionReceipts<F, C, D>,
) -> Result<(AllProof<F, C, D>, Rc<RefCell<AssumptionUsage<F, C, D>>>)>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F=F>,
{
    let (proof, _outputs, receipts) =
        prove_with_output_and_assumptions(all_stark, kernel, config, timing, assumptions)?;
    Ok((proof, receipts))
}

/// Generate traces, then create all STARK proofs. Returns information about the post-state,
/// intended for debugging, in addition to the proof.
pub fn prove_with_outputs<F, C, const D: usize>(
    all_stark: &AllStark<F, D>,
    kernel: &Kernel,
    config: &StarkConfig,
    timing: &mut TimingTree,
) -> Result<(AllProof<F, C, D>, GenerationOutputs)>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F=F>,
{
    let (traces, public_values, outputs) = timed!(
        timing,
        log::Level::Info,
        "generate all traces",
        generate_traces::<F, C, D>(all_stark, kernel, config, timing)?
    );

    traces.iter().for_each(|t| {
        log::info!(
            "Trace steps: {}  lengths {} iten_len: {}",
            kernel.program.step,
            t.len(),
            t[0].len()
        );
    });

    let proof = prove_with_traces(all_stark, config, traces, public_values, timing)?;
    Ok((proof, outputs))
}

fn fast_copy<F: RichField>(vec_polys: &Vec<PolynomialValues<F>>) -> Vec<PolynomialValues<F>> {
    println!("fast_copy {:?} {:?}", vec_polys.len(), vec_polys[0].values.len());
    vec_polys.par_iter().map(|poly| poly.clone()).collect()
}

/// Generate traces, then create all STARK proofs. Returns information about the post-state,
/// intended for debugging, in addition to the proof.
pub fn prove_with_output_and_assumptions<F, C, const D: usize>(
    all_stark: &AllStark<F, D>,
    kernel: &Kernel,
    config: &StarkConfig,
    timing: &mut TimingTree,
    assumptions: AssumptionReceipts<F, C, D>,
) -> Result<(
    AllProof<F, C, D>,
    GenerationOutputs,
    Rc<RefCell<AssumptionUsage<F, C, D>>>,
)>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F=F>,
{
    let (traces, public_values, outputs, receipts) = timed!(
        timing,
        "generate all traces",
        generate_traces_with_assumptions::<F, C, D>(
            all_stark,
            kernel,
            config,
            timing,
            assumptions
        )?
    );

    let proof = prove_with_traces(all_stark, config, traces, public_values, timing)?;
    Ok((proof, outputs, receipts))
}

/// Compute all STARK proofs.
pub(crate) fn prove_with_traces<F, C, const D: usize>(
    all_stark: &AllStark<F, D>,
    config: &StarkConfig,
    trace_poly_values: [Vec<PolynomialValues<F>>; NUM_TABLES],
    public_values: PublicValues,
    timing: &mut TimingTree,
) -> Result<AllProof<F, C, D>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F=F>,
{
    let rate_bits = config.fri_config.rate_bits;
    let cap_height = config.fri_config.cap_height;

    timing.push("clone polys", log::Level::Info);
    let trace_poly_values_clone = trace_poly_values
        .iter()
        .map(|a| fast_copy(a))
        .collect::<Vec<_>>();
    timing.pop();
    let trace_commitments = timed!(
        timing,
        log::Level::Info,
        "compute all trace commitments",
        trace_poly_values_clone
            .into_iter()
            .zip_eq(Table::all())
            .map(|(trace, table)| {
                  let mut total_item: u64 = 0;
                trace.iter().for_each(|item|{
                    total_item += item.len() as u64;
                });
                log::info!(
                    "prove_with_traces trace_len: {} total_item {}, item_size: {} rate_bits: {} cap_height: {} table: {:?}",
                    trace.len(),
                    total_item,
                    std::mem::size_of::<F>(),
                    rate_bits,
                    cap_height,
                    table
                );
                // 2**25 33554432
                if trace[0].len() <= 33554432usize {
                    timed!(
                        timing,
                        &format!("gpu compute trace commitment for {:?}", table),
                        PolynomialBatch::<F, C, D>::from_values_cuda(
                            // TODO: Cloning this isn't great; consider having `from_values` accept a reference,
                            // or having `compute_permutation_z_polys` read trace values from the `PolynomialBatch`.
                            trace, rate_bits, false, cap_height, timing, None,
                        )
                    )
                } else {
                    timed!(
                        timing,
                        &format!("cpu compute trace commitment for {:?}", table),
                        PolynomialBatch::<F, C, D>::from_values(
                            // TODO: Cloning this isn't great; consider having `from_values` accept a reference,
                            // or having `compute_permutation_z_polys` read trace values from the `PolynomialBatch`.
                            trace.clone(),
                            rate_bits,
                            false,
                            cap_height,
                            timing,
                            None,
                        )
                    )
                }
            })
            .collect::<Vec<_>>()
    );

    log::debug!("trace_commitments: {}", trace_commitments.len());

    #[cfg(any(feature = "test", test))]
    {
        log::debug!("check_ctls...");
        check_ctls(&trace_poly_values, &all_stark.cross_table_lookups);
        log::debug!("check_ctls done.");
    }

    let trace_caps = trace_commitments
        .iter()
        .map(|c| c.merkle_tree.cap.clone())
        .collect::<Vec<_>>();
    let mut challenger = Challenger::<F, C::Hasher>::new();
    for cap in &trace_caps {
        challenger.observe_cap(cap);
    }

    observe_public_values::<F, C, D>(&mut challenger, &public_values)
        .map_err(|_| anyhow::Error::msg("Invalid conversion of public values."))?;

    let ctl_challenges = get_grand_product_challenge_set(&mut challenger, config.num_challenges);
    let ctl_data_per_table = timed!(
        timing,
        log::Level::Info,
        "compute CTL data",
        cross_table_lookup_data::<F, D>(
            &trace_poly_values,
            &all_stark.cross_table_lookups,
            &ctl_challenges,
            all_stark.arithmetic_stark.constraint_degree()
        )
    );

    let stark_proofs = timed!(
        timing,
        log::Level::Info,
        "compute all proofs given commitments",
        prove_with_commitments(
            all_stark,
            config,
            trace_poly_values,
            trace_commitments,
            ctl_data_per_table,
            &mut challenger,
            &ctl_challenges,
            timing
        )?
    );

    /*
    #[cfg(test)]
    {
        check_ctls(
            &trace_poly_values,
            &all_stark.cross_table_lookups,
        );
    }
    */

    Ok(AllProof {
        stark_proofs,
        ctl_challenges,
        public_values,
    })
}

fn prove_with_commitments<F, C, const D: usize>(
    all_stark: &AllStark<F, D>,
    config: &StarkConfig,
    trace_poly_values: [Vec<PolynomialValues<F>>; NUM_TABLES],
    trace_commitments: Vec<PolynomialBatch<F, C, D>>,
    ctl_data_per_table: [CtlData<F>; NUM_TABLES],
    challenger: &mut Challenger<F, C::Hasher>,
    ctl_challenges: &GrandProductChallengeSet<F>,
    timing: &mut TimingTree,
) -> Result<[StarkProofWithMetadata<F, C, D>; NUM_TABLES]>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F=F>,
{
    let arithmetic_proof = timed!(
        timing,
        log::Level::Info,
        "prove Arithmetic STARK",
        prove_single_table(
            &all_stark.arithmetic_stark,
            config,
            &trace_poly_values[Table::Arithmetic as usize],
            &trace_commitments[Table::Arithmetic as usize],
            &ctl_data_per_table[Table::Arithmetic as usize],
            ctl_challenges,
            challenger,
            timing,
        )?
    );
    let cpu_proof = timed!(
        timing,
        log::Level::Info,
        "prove CPU STARK",
        prove_single_table(
            &all_stark.cpu_stark,
            config,
            &trace_poly_values[Table::Cpu as usize],
            &trace_commitments[Table::Cpu as usize],
            &ctl_data_per_table[Table::Cpu as usize],
            ctl_challenges,
            challenger,
            timing,
        )?
    );

    let poseidon_proof = timed!(
        timing,
        log::Level::Info,
        "prove Poseidon STARK",
        prove_single_table(
            &all_stark.poseidon_stark,
            config,
            &trace_poly_values[Table::Poseidon as usize],
            &trace_commitments[Table::Poseidon as usize],
            &ctl_data_per_table[Table::Poseidon as usize],
            ctl_challenges,
            challenger,
            timing,
        )?
    );
    let poseidon_sponge_proof = timed!(
        timing,
        log::Level::Info,
        "prove Poseidon sponge STARK",
        prove_single_table(
            &all_stark.poseidon_sponge_stark,
            config,
            &trace_poly_values[Table::PoseidonSponge as usize],
            &trace_commitments[Table::PoseidonSponge as usize],
            &ctl_data_per_table[Table::PoseidonSponge as usize],
            ctl_challenges,
            challenger,
            timing,
        )?
    );

    let keccak_proof = timed!(
        timing,
        log::Level::Info,
        "prove Keccak STARK",
        prove_single_table(
            &all_stark.keccak_stark,
            config,
            &trace_poly_values[Table::Keccak as usize],
            &trace_commitments[Table::Keccak as usize],
            &ctl_data_per_table[Table::Keccak as usize],
            ctl_challenges,
            challenger,
            timing,
        )?
    );
    let keccak_sponge_proof = timed!(
        timing,
        log::Level::Info,
        "prove Keccak sponge STARK",
        prove_single_table(
            &all_stark.keccak_sponge_stark,
            config,
            &trace_poly_values[Table::KeccakSponge as usize],
            &trace_commitments[Table::KeccakSponge as usize],
            &ctl_data_per_table[Table::KeccakSponge as usize],
            ctl_challenges,
            challenger,
            timing,
        )?
    );

    let sha_extend_proof = timed!(
        timing,
        log::Level::Info,
        "prove SHA Extend STARK",
        prove_single_table(
            &all_stark.sha_extend_stark,
            config,
            &trace_poly_values[Table::ShaExtend as usize],
            &trace_commitments[Table::ShaExtend as usize],
            &ctl_data_per_table[Table::ShaExtend as usize],
            ctl_challenges,
            challenger,
            timing,
        )?
    );

    let sha_extend_sponge_proof = timed!(
        timing,
        log::Level::Info,
        "prove SHA Extend sponge STARK",
        prove_single_table(
            &all_stark.sha_extend_sponge_stark,
            config,
            &trace_poly_values[Table::ShaExtendSponge as usize],
            &trace_commitments[Table::ShaExtendSponge as usize],
            &ctl_data_per_table[Table::ShaExtendSponge as usize],
            ctl_challenges,
            challenger,
            timing,
        )?
    );

    let sha_compress_proof = timed!(
        timing,
        log::Level::Info,
        "prove SHA Compress STARK",
        prove_single_table(
            &all_stark.sha_compress_stark,
            config,
            &trace_poly_values[Table::ShaCompress as usize],
            &trace_commitments[Table::ShaCompress as usize],
            &ctl_data_per_table[Table::ShaCompress as usize],
            ctl_challenges,
            challenger,
            timing,
        )?
    );

    let sha_compress_sponge_proof = timed!(
        timing,
        log::Level::Info,
        "prove SHA Compress sponge STARK",
        prove_single_table(
            &all_stark.sha_compress_sponge_stark,
            config,
            &trace_poly_values[Table::ShaCompressSponge as usize],
            &trace_commitments[Table::ShaCompressSponge as usize],
            &ctl_data_per_table[Table::ShaCompressSponge as usize],
            ctl_challenges,
            challenger,
            timing,
        )?
    );

    let logic_proof = timed!(
        timing,
        log::Level::Info,
        "prove Logic STARK",
        prove_single_table(
            &all_stark.logic_stark,
            config,
            &trace_poly_values[Table::Logic as usize],
            &trace_commitments[Table::Logic as usize],
            &ctl_data_per_table[Table::Logic as usize],
            ctl_challenges,
            challenger,
            timing,
        )?
    );
    let memory_proof = timed!(
        timing,
        log::Level::Info,
        "prove Memory STARK",
        prove_single_table(
            &all_stark.memory_stark,
            config,
            &trace_poly_values[Table::Memory as usize],
            &trace_commitments[Table::Memory as usize],
            &ctl_data_per_table[Table::Memory as usize],
            ctl_challenges,
            challenger,
            timing,
        )?
    );

    Ok([
        arithmetic_proof,
        cpu_proof,
        poseidon_proof,
        poseidon_sponge_proof,
        keccak_proof,
        keccak_sponge_proof,
        sha_extend_proof,
        sha_extend_sponge_proof,
        sha_compress_proof,
        sha_compress_sponge_proof,
        logic_proof,
        memory_proof,
    ])
}

/// Compute proof for a single STARK table.
pub(crate) fn prove_single_table<F, C, S, const D: usize>(
    stark: &S,
    config: &StarkConfig,
    trace_poly_values: &[PolynomialValues<F>],
    trace_commitment: &PolynomialBatch<F, C, D>,
    ctl_data: &CtlData<F>,
    ctl_challenges: &GrandProductChallengeSet<F>,
    challenger: &mut Challenger<F, C::Hasher>,
    timing: &mut TimingTree,
) -> Result<StarkProofWithMetadata<F, C, D>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F=F>,
    S: Stark<F, D>,
{
    let degree = trace_poly_values[0].len();
    let degree_bits = log2_strict(degree);
    let fri_params = config.fri_params(degree_bits);
    let rate_bits = config.fri_config.rate_bits;
    let cap_height = config.fri_config.cap_height;
    assert!(
        fri_params.total_arities() <= degree_bits + rate_bits - cap_height,
        "FRI total reduction arity is too large.",
    );

    let init_challenger_state = challenger.compact();

    let constraint_degree = stark.constraint_degree();
    let lookup_challenges = stark.uses_lookups().then(|| {
        ctl_challenges
            .challenges
            .iter()
            .map(|ch| ch.beta)
            .collect::<Vec<_>>()
    });
    let lookups = stark.lookups();
    let lookup_helper_columns = timed!(
        timing,
        "compute lookup helper columns",
        lookup_challenges.as_ref().map(|challenges| {
            let mut columns = Vec::new();
            for lookup in &lookups {
                for &challenge in challenges {
                    columns.extend(lookup_helper_columns(
                        lookup,
                        trace_poly_values,
                        challenge,
                        constraint_degree,
                    ));
                }
            }
            columns
        })
    );
    let num_lookup_columns = lookup_helper_columns.as_ref().map(|v| v.len()).unwrap_or(0);

    let auxiliary_polys = match lookup_helper_columns {
        None => {
            let mut ctl_polys = ctl_data.ctl_helper_polys();
            ctl_polys.extend(ctl_data.ctl_z_polys());
            ctl_polys
        }
        Some(mut lookup_columns) => {
            lookup_columns.extend(ctl_data.ctl_helper_polys());
            lookup_columns.extend(ctl_data.ctl_z_polys());
            lookup_columns
        }
    };
    assert!(!auxiliary_polys.is_empty(), "No CTL?");

    let mut total_item: u64 = 0;
    auxiliary_polys.iter().for_each(|item| {
        total_item += item.len() as u64;
    });

    log::info!(
        "prove_single_table {} total_item {}, item_size: {} rate_bits: {} cap_height: {}",
        auxiliary_polys.len(),
        total_item,
        std::mem::size_of::<F>(),
        rate_bits,
        config.fri_config.cap_height,
    );

    // 2**25 33554432
    let auxiliary_polys_commitment = if auxiliary_polys[0].len() <= 33554432usize {
        timed!(
            timing,
                        log::Level::Info,
            "compute auxiliary polynomials commitment",
            PolynomialBatch::from_values_cuda(
                auxiliary_polys,
                rate_bits,
                false,
                config.fri_config.cap_height,
                timing,
                None,
            )
        )
    } else {
        timed!(
            timing,
            "compute auxiliary polynomials commitment",
            PolynomialBatch::from_values(
                auxiliary_polys,
                rate_bits,
                false,
                config.fri_config.cap_height,
                timing,
                None,
            )
        )
    };

    let auxiliary_polys_cap = auxiliary_polys_commitment.merkle_tree.cap.clone();
    challenger.observe_cap(&auxiliary_polys_cap);

    let alphas = challenger.get_n_challenges(config.num_challenges);
    let num_ctl_polys = ctl_data.num_ctl_helper_polys();
    if cfg!(test) {
        check_constraints(
            stark,
            trace_commitment,
            &auxiliary_polys_commitment,
            lookup_challenges.as_ref(),
            &lookups,
            ctl_data,
            alphas.clone(),
            degree_bits,
            num_lookup_columns,
            &num_ctl_polys,
        );
    }


    log::info!("trace_commitment.polynomials[0].len: {}, auxiliary_polys_commitment.polynomials[0].len: {}",
        trace_commitment.polynomials[0].len(), auxiliary_polys_commitment.polynomials[0].len());
    let use_gpu = trace_commitment.polynomials[0].len() < 4194304usize && auxiliary_polys_commitment.polynomials[0].len() < 4194304usize;
    let quotient_polys = if use_gpu {
        timed!(
            timing,
            log::Level::Info,
            "compute quotient polys",
            compute_quotient_polys_cuda::<F, <F as Packable>::Packing, C, S, D>(
                stark,
                trace_commitment,
                &auxiliary_polys_commitment,
                lookup_challenges.as_ref(),
                &lookups,
                ctl_data,
                alphas,
                degree_bits,
                num_lookup_columns,
                &num_ctl_polys,
                config,
                timing,
            )
        )
    } else {
        timed!(
            timing,
            log::Level::Info,
            "compute quotient polys",
            compute_quotient_polys::<F, <F as Packable>::Packing, C, S, D>(
                stark,
                trace_commitment,
                &auxiliary_polys_commitment,
                lookup_challenges.as_ref(),
                &lookups,
                ctl_data,
                alphas,
                degree_bits,
                num_lookup_columns,
                &num_ctl_polys,
                config,
            )
        )
    };

    let all_quotient_chunks: Vec<PolynomialCoeffs<F>> = timed!(
        timing,
         log::Level::Info,
        "split quotient polys",
        quotient_polys
            .into_par_iter()
            .flat_map(|mut quotient_poly| {
                quotient_poly
                    .trim_to_len(degree * stark.quotient_degree_factor())
                    .expect(
                        "Quotient has failed, the vanishing polynomial is not divisible by Z_H",
                    );
                // Split quotient into degree-n chunks.
                quotient_poly.chunks(degree)
            })
            .collect()
    );
    let quotient_commitment = if all_quotient_chunks[0].len() <= 33554432usize {
        timed!(
            timing,
                        log::Level::Info,
            "compute quotient commitment",
            PolynomialBatch::from_coeffs_cuda(
                all_quotient_chunks,
                rate_bits,
                false,
                config.fri_config.cap_height,
                timing,
                None,
            )
        )
    } else {
        timed!(
            timing,
            log::Level::Info,
            "compute quotient commitment",
            PolynomialBatch::from_coeffs(
                all_quotient_chunks,
                rate_bits,
                false,
                config.fri_config.cap_height,
                timing,
                None,
            )
        )
    };
    let quotient_polys_cap = quotient_commitment.merkle_tree.cap.clone();
    challenger.observe_cap(&quotient_polys_cap);

    let zeta = challenger.get_extension_challenge::<D>();
    // To avoid leaking witness data, we want to ensure that our opening locations, `zeta` and
    // `g * zeta`, are not in our subgroup `H`. It suffices to check `zeta` only, since
    // `(g * zeta)^n = zeta^n`, where `n` is the order of `g`.
    let g = F::primitive_root_of_unity(degree_bits);
    ensure!(
        zeta.exp_power_of_2(degree_bits) != F::Extension::ONE,
        "Opening point is in the subgroup."
    );

    let openings = StarkOpeningSet::new(
        zeta,
        g,
        trace_commitment,
        &auxiliary_polys_commitment,
        &quotient_commitment,
        stark.num_lookup_helper_columns(config),
        &num_ctl_polys,
    );
    challenger.observe_openings(&openings.to_fri_openings());

    let initial_merkle_trees = vec![
        trace_commitment,
        &auxiliary_polys_commitment,
        &quotient_commitment,
    ];

    let opening_proof = timed!(
        timing,
         log::Level::Info,
        "compute openings proof",
        // PolynomialBatch::prove_openings(
        PolynomialBatch::prove_openings_cuda(
            &stark.fri_instance(zeta, g, num_ctl_polys.iter().sum(), num_ctl_polys, config),
            &initial_merkle_trees,
            challenger,
            &fri_params,
            timing,
        )
    );

    let proof = StarkProof {
        trace_cap: trace_commitment.merkle_tree.cap.clone(),
        auxiliary_polys_cap,
        quotient_polys_cap,
        openings,
        opening_proof,
    };
    Ok(StarkProofWithMetadata {
        init_challenger_state,
        proof,
    })
}

/// Computes the quotient polynomials `(sum alpha^i C_i(x)) / Z_H(x)` for `alpha` in `alphas`,
/// where the `C_i`s are the Stark constraints.
fn compute_quotient_polys<'a, F, P, C, S, const D: usize>(
    stark: &S,
    trace_commitment: &'a PolynomialBatch<F, C, D>,
    auxiliary_polys_commitment: &'a PolynomialBatch<F, C, D>,
    lookup_challenges: Option<&'a Vec<F>>,
    lookups: &[Lookup<F>],
    ctl_data: &CtlData<F>,
    alphas: Vec<F>,
    degree_bits: usize,
    num_lookup_columns: usize,
    num_ctl_columns: &[usize],
    config: &StarkConfig,
) -> Vec<PolynomialCoeffs<F>>
where
    F: RichField + Extendable<D>,
    P: PackedField<Scalar=F>,
    C: GenericConfig<D, F=F>,
    S: Stark<F, D>,
{
    let degree = 1 << degree_bits;
    let rate_bits = config.fri_config.rate_bits;
    let total_num_helper_cols: usize = num_ctl_columns.iter().sum();

    let quotient_degree_bits = log2_ceil(stark.quotient_degree_factor());
    assert!(
        quotient_degree_bits <= rate_bits,
        "Having constraints of degree higher than the rate is not supported yet."
    );
    let step = 1 << (rate_bits - quotient_degree_bits);
    // When opening the `Z`s polys at the "next" point, need to look at the point `next_step` steps away.
    let next_step = 1 << quotient_degree_bits;

    // Evaluation of the first Lagrange polynomial on the LDE domain.
    let lagrange_first = PolynomialValues::selector(degree, 0).lde_onto_coset(quotient_degree_bits);
    // Evaluation of the last Lagrange polynomial on the LDE domain.
    let lagrange_last =
        PolynomialValues::selector(degree, degree - 1).lde_onto_coset(quotient_degree_bits);

    let z_h_on_coset = ZeroPolyOnCoset::<F>::new(degree_bits, quotient_degree_bits);

    // Retrieve the LDE values at index `i`.
    let get_trace_values_packed =
        |i_start| -> Vec<P> { trace_commitment.get_lde_values_packed(i_start, step) };

    // Last element of the subgroup.
    let last = F::primitive_root_of_unity(degree_bits).inverse();
    let size = degree << quotient_degree_bits;
    let coset = F::cyclic_subgroup_coset_known_order(
        F::primitive_root_of_unity(degree_bits + quotient_degree_bits),
        F::coset_shift(),
        size,
    );

    // We will step by `P::WIDTH`, and in each iteration, evaluate the quotient polynomial at
    // a batch of `P::WIDTH` points.
    let quotient_values = (0..size)
        .into_par_iter()
        .step_by(P::WIDTH)
        .flat_map_iter(|i_start| {
            let i_next_start = (i_start + next_step) % size;
            let i_range = i_start..i_start + P::WIDTH;

            let x = *P::from_slice(&coset[i_range.clone()]);
            let z_last = x - last;
            let lagrange_basis_first = *P::from_slice(&lagrange_first.values[i_range.clone()]);
            let lagrange_basis_last = *P::from_slice(&lagrange_last.values[i_range]);

            let mut consumer = ConstraintConsumer::new(
                alphas.clone(),
                z_last,
                lagrange_basis_first,
                lagrange_basis_last,
            );
            let vars = S::EvaluationFrame::from_values(
                &get_trace_values_packed(i_start),
                &get_trace_values_packed(i_next_start),
            );
            let lookup_vars = lookup_challenges.map(|challenges| LookupCheckVars {
                local_values: auxiliary_polys_commitment.get_lde_values_packed(i_start, step)
                    [..num_lookup_columns]
                    .to_vec(),
                next_values: auxiliary_polys_commitment.get_lde_values_packed(i_next_start, step),
                challenges: challenges.to_vec(),
            });
            let mut start_index = 0;
            let ctl_vars = ctl_data
                .zs_columns
                .iter()
                .enumerate()
                .map(|(i, zs_columns)| {
                    let num_ctl_helper_cols = num_ctl_columns[i];
                    let helper_columns = auxiliary_polys_commitment
                        .get_lde_values_packed(i_start, step)[num_lookup_columns
                        + start_index
                        ..num_lookup_columns + start_index + num_ctl_helper_cols]
                        .to_vec();

                    let ctl_vars = CtlCheckVars::<F, F, P, 1> {
                        helper_columns,
                        local_z: auxiliary_polys_commitment.get_lde_values_packed(i_start, step)
                            [num_lookup_columns + total_num_helper_cols + i],
                        next_z: auxiliary_polys_commitment
                            .get_lde_values_packed(i_next_start, step)
                            [num_lookup_columns + total_num_helper_cols + i],
                        challenges: zs_columns.challenge,
                        columns: zs_columns.columns.clone(),
                        filter: zs_columns.filter.clone(),
                    };

                    start_index += num_ctl_helper_cols;

                    ctl_vars
                })
                .collect::<Vec<_>>();
            eval_vanishing_poly::<F, F, P, S, D, 1>(
                stark,
                &vars,
                lookups,
                lookup_vars,
                &ctl_vars,
                &mut consumer,
            );
            let mut constraints_evals = consumer.accumulators();
            // We divide the constraints evaluations by `Z_H(x)`.
            let denominator_inv: P = z_h_on_coset.eval_inverse_packed(i_start);
            for eval in &mut constraints_evals {
                *eval *= denominator_inv;
            }

            let num_challenges = alphas.len();

            (0..P::WIDTH).map(move |i| {
                (0..num_challenges)
                    .map(|j| constraints_evals[j].as_slice()[i])
                    .collect()
            })
        })
        .collect::<Vec<_>>();

    transpose(&quotient_values)
        .into_par_iter()
        .map(PolynomialValues::new)
        .map(|values| values.coset_ifft(F::coset_shift()))
        .collect()
}

/// Check that all constraints evaluate to zero on `H`.
/// Can also be used to check the degree of the constraints by evaluating on a larger subgroup.
fn check_constraints<'a, F, C, S, const D: usize>(
    stark: &S,
    trace_commitment: &'a PolynomialBatch<F, C, D>,
    auxiliary_commitment: &'a PolynomialBatch<F, C, D>,
    lookup_challenges: Option<&'a Vec<F>>,
    lookups: &[Lookup<F>],
    ctl_data: &CtlData<F>,
    alphas: Vec<F>,
    degree_bits: usize,
    num_lookup_columns: usize,
    num_ctl_helper_cols: &[usize],
) where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F=F>,
    S: Stark<F, D>,
{
    let degree = 1 << degree_bits;
    let rate_bits = 0; // Set this to higher value to check constraint degree.
    let total_num_helper_cols: usize = num_ctl_helper_cols.iter().sum();

    let size = degree << rate_bits;
    let step = 1 << rate_bits;

    // Evaluation of the first Lagrange polynomial.
    let lagrange_first = PolynomialValues::selector(degree, 0).lde(rate_bits);
    // Evaluation of the last Lagrange polynomial.
    let lagrange_last = PolynomialValues::selector(degree, degree - 1).lde(rate_bits);

    let subgroup = F::two_adic_subgroup(degree_bits + rate_bits);

    // Get the evaluations of a batch of polynomials over our subgroup.
    let get_subgroup_evals = |comm: &PolynomialBatch<F, C, D>| -> Vec<Vec<F>> {
        let values = comm
            .polynomials
            .par_iter()
            .map(|coeffs| coeffs.clone().fft().values)
            .collect::<Vec<_>>();
        transpose(&values)
    };

    let trace_subgroup_evals = get_subgroup_evals(trace_commitment);
    let auxiliary_subgroup_evals = get_subgroup_evals(auxiliary_commitment);

    // Last element of the subgroup.
    let last = F::primitive_root_of_unity(degree_bits).inverse();

    let constraint_values = (0..size)
        .map(|i| {
            let i_next = (i + step) % size;

            let x = subgroup[i];
            let z_last = x - last;
            let lagrange_basis_first = lagrange_first.values[i];
            let lagrange_basis_last = lagrange_last.values[i];

            let mut consumer = ConstraintConsumer::new(
                alphas.clone(),
                z_last,
                lagrange_basis_first,
                lagrange_basis_last,
            );
            let vars = S::EvaluationFrame::from_values(
                &trace_subgroup_evals[i],
                &trace_subgroup_evals[i_next],
            );
            let lookup_vars = lookup_challenges.map(|challenges| LookupCheckVars {
                local_values: auxiliary_subgroup_evals[i][..num_lookup_columns].to_vec(),
                next_values: auxiliary_subgroup_evals[i_next][..num_lookup_columns].to_vec(),
                challenges: challenges.to_vec(),
            });

            let mut start_index = 0;
            let ctl_vars = ctl_data
                .zs_columns
                .iter()
                .enumerate()
                .map(|(iii, zs_columns)| {
                    let num_helper_cols = num_ctl_helper_cols[iii];
                    let helper_columns = auxiliary_subgroup_evals[i][num_lookup_columns
                        + start_index
                        ..num_lookup_columns + start_index + num_helper_cols]
                        .to_vec();
                    let ctl_vars = CtlCheckVars::<F, F, F, 1> {
                        helper_columns,
                        local_z: auxiliary_subgroup_evals[i]
                            [num_lookup_columns + total_num_helper_cols + iii],
                        next_z: auxiliary_subgroup_evals[i_next]
                            [num_lookup_columns + total_num_helper_cols + iii],
                        challenges: zs_columns.challenge,
                        columns: zs_columns.columns.clone(),
                        filter: zs_columns.filter.clone(),
                    };

                    start_index += num_helper_cols;

                    ctl_vars
                })
                .collect::<Vec<_>>();
            eval_vanishing_poly::<F, F, F, S, D, 1>(
                stark,
                &vars,
                lookups,
                lookup_vars,
                &ctl_vars,
                &mut consumer,
            );
            consumer.accumulators()
        })
        .collect::<Vec<_>>();

    for v in constraint_values {
        assert!(
            v.iter().all(|x| x.is_zero()),
            "Constraint failed in {}",
            type_name::<S>()
        );
    }
}

fn compute_quotient_polys_cuda<'a, F, P, C, S, const D: usize>(
    stark: &S,
    trace_commitment: &'a PolynomialBatch<F, C, D>,
    auxiliary_polys_commitment: &'a PolynomialBatch<F, C, D>,
    lookup_challenges: Option<&'a Vec<F>>,
    lookups: &[Lookup<F>],
    ctl_data: &CtlData<F>,
    alphas: Vec<F>,
    degree_bits: usize,
    num_lookup_columns: usize,
    num_ctl_columns: &[usize],
    config: &StarkConfig,
    timing: &mut TimingTree,
) -> Vec<PolynomialCoeffs<F>>
where
    F: RichField + Extendable<D>,
    P: PackedField<Scalar=F>,
    C: GenericConfig<D, F=F>,
    S: Stark<F, D>,
{
    use core::any::TypeId;
    use std::mem::transmute;
    use plonky2::compute_quotient_polys_cuda_warp;
    use std::ptr;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    // println!();
    // println!();
    // println!();
    if TypeId::of::<F>() != TypeId::of::<GoldilocksField>()
        || TypeId::of::<PoseidonGoldilocksConfig>() != TypeId::of::<C>()
        || D != 2
        || trace_commitment.blinding != false
        || auxiliary_polys_commitment.blinding != false
        || stark.get_type() == 0 // 0 for Keccak and KeccakSponge type
        || alphas.len() != 2
    {
        println!("type mismatch! go to compute_quotient_polys!!!");
        return compute_quotient_polys::<F, <F as Packable>::Packing, C, S, D>(
            stark,
            trace_commitment,
            &auxiliary_polys_commitment,
            lookup_challenges,
            &lookups,
            ctl_data,
            alphas,
            degree_bits,
            num_lookup_columns,
            num_ctl_columns,
            config,
        );
    }
    // -------------------------------------------------------------------- //
    timing.push("0 compute_quotient_values data parse", log::Level::Info);
    let degree = 1 << degree_bits;
    let rate_bits = config.fri_config.rate_bits;
    let quotient_degree_bits = log2_ceil(stark.quotient_degree_factor());
    assert!(
        quotient_degree_bits <= rate_bits,
        "Having constraints of degree higher than the rate is not support
        ed yet."
    );
    let alpha_len = alphas.len();
    let stark_type = stark.get_type();
    let abstract_field_vec = plonky2::field::abstract_field::SIMPLE_STARKS_ABSTRACT_FIELD_VEC
        .lock()
        .unwrap();
    let ops_streams = abstract_field_vec[stark_type - 1].clone().unwrap();
    let ops_streams_len = ops_streams.len();
    let mut ops_streams_vec: Vec<u64> = Vec::new();
    assert!(ops_streams_len < 16000, "ops_streams_len must < 16000");
    for node in ops_streams {
        ops_streams_vec.push(node.op);
        ops_streams_vec.push(node.tmp1_type);
        ops_streams_vec.push(node.tmp1_idx);
        ops_streams_vec.push(node.tmp1_f);
        ops_streams_vec.push(node.tmp2_type);
        ops_streams_vec.push(node.tmp2_idx);
        ops_streams_vec.push(node.tmp2_f);
    }
    let alphas_gf: *const GoldilocksField = unsafe { transmute(alphas.as_ptr()) };
    let trace_commitment_polynum = trace_commitment.merkle_tree.leave_size;
    let trace_commitment_polylen = trace_commitment.merkle_tree.leaves_len;
    let trace_commitment_leaves_gf: *mut GoldilocksField =
        unsafe {
            transmute(trace_commitment.merkle_tree.leaves.as_ptr())
        }; // poly_len * poly_num
    let auxiliary_polys_commitment_polynum = auxiliary_polys_commitment.merkle_tree.leave_size;
    let auxiliary_polys_commitment_polylen = auxiliary_polys_commitment.merkle_tree.leaves_len;
    let auxiliary_polys_commitment_leaves_gf: *mut GoldilocksField =
        unsafe { transmute(auxiliary_polys_commitment.merkle_tree.leaves.as_ptr()) };
    assert!(lookups.len() <= 1, "lookups.len() must <= 1");
    let step2_exec_flag = lookups.len() == 1;
    let mut lookups_columns_linear_idx: Vec<usize> = Vec::new();
    let mut lookups_columns_linear_f: Vec<F> = Vec::new();
    let mut lookups_columns_len = 0;
    if step2_exec_flag {
        // lookups-columns
        lookups_columns_len = lookups[0].columns.len();
        for c in &lookups[0].columns {
            assert!(c.linear_combination.len() == 1);
            assert!(c.next_row_linear_combination.len() == 0);
            assert!(c.constant == F::ZERO);
            lookups_columns_linear_idx.push(c.linear_combination[0].0);
            lookups_columns_linear_f.push(c.linear_combination[0].1);
        }
        // lookups-table_column
        let table_column = &lookups[0].table_column;
        assert!(table_column.linear_combination.len() == 1);
        assert!(table_column.next_row_linear_combination.len() == 0);
        assert!(table_column.constant == F::ZEROS);
        lookups_columns_linear_idx.push(table_column.linear_combination[0].0);
        lookups_columns_linear_f.push(table_column.linear_combination[0].1);
        // lookups-frequencies_column
        let frequencies_column = &lookups[0].frequencies_column;
        assert!(frequencies_column.linear_combination.len() == 1);
        assert!(frequencies_column.next_row_linear_combination.len() == 0);
        assert!(frequencies_column.constant == F::ZEROS);
        lookups_columns_linear_idx.push(frequencies_column.linear_combination[0].0);
        lookups_columns_linear_f.push(frequencies_column.linear_combination[0].1);
        for filter in &lookups[0].filter_columns {
            assert!(filter.is_none());
        }
    }
    let lookups_columns_linear_gf: *mut GoldilocksField = if !lookups_columns_linear_f.is_empty() {
        unsafe { transmute(&mut lookups_columns_linear_f[0]) }
    } else {
        ptr::null_mut()
    };

    let mut lookup_vars_lookup_challenges_len = 0;
    let mut lookup_vars_lookup_challenges_f: Vec<F> = Vec::new();
    if !lookup_challenges.is_none() {
        for data in lookup_challenges.unwrap() {
            lookup_vars_lookup_challenges_f.push(*data);
        }
        lookup_vars_lookup_challenges_len = lookup_vars_lookup_challenges_f.len();
    }
    let lookup_vars_lookup_challenges_gf: *mut GoldilocksField =
        if lookup_vars_lookup_challenges_len > 0 {
            unsafe { transmute(&mut lookup_vars_lookup_challenges_f[0]) }
        } else {
            ptr::null_mut()
        };

    let ctl_data_len = ctl_data.zs_columns.len();
    let mut each_ctl_vars_columns_dim1: Vec<usize> = vec![0; ctl_data_len];
    let mut each_ctl_vars_columns_dim2: Vec<usize> = vec![0; ctl_data_len];
    let mut ctl_data_challenges_beta_gamma: Vec<F> = vec![F::ZERO; ctl_data_len * 2];
    let mut ctl_data_columns_constant_f: Vec<F> = Vec::new(); //总⻓度 sum_i(each_ctl_vars_columns_dim1[i] * each_ctl_vars_columns_dim2[i])
    let mut ctl_data_columns_constant_f_cursor: Vec<usize> = vec![0; ctl_data_len];
    let mut ctl_data_columns_linear_i: Vec<usize> = Vec::new();
    let mut ctl_data_columns_linear_f: Vec<F> = Vec::new();
    let mut ctl_data_columns_linear_f_len: Vec<usize> = Vec::new(); //总⻓度 sum_i(each_ctl_vars_columns_dim1[i] * each_ctl_vars_columns_dim2[i])
    let mut ctl_data_columns_linear_f_cursor: Vec<usize> = Vec::new(); //总⻓度 sum_i(each_ctl_vars_columns_dim1[i] * each_ctl_vars_columns_dim2[i])
    let mut ctl_data_filter_constant_f: Vec<F> = Vec::new(); //总⻓度 sum_i(each_ctl_vars_columns_dim1[i] * 1)
    let mut ctl_data_filter_constant_f_cursor: Vec<usize> = vec![0; ctl_data_len];
    let mut ctl_data_filter_linear_i: Vec<usize> = Vec::new();
    let mut ctl_data_filter_linear_f: Vec<F> = Vec::new();
    let mut ctl_data_filter_linear_f_len: Vec<usize> = Vec::new(); //总⻓度 sum_i(each_ctl_vars_columns_dim1[i] * 1)
    let mut ctl_data_filter_linear_f_cursor: Vec<usize> = Vec::new(); //总⻓度 sum_i(each_ctl_vars_columns_dim1[i] * 1)
    for i in 0..ctl_data_len {
        ctl_data_challenges_beta_gamma[i * 2] = ctl_data.zs_columns[i].challenge.beta;
        ctl_data_challenges_beta_gamma[i * 2 + 1] = ctl_data.zs_columns[i].challenge.gamma;
        each_ctl_vars_columns_dim1[i] = ctl_data.zs_columns[i].columns.len();
        each_ctl_vars_columns_dim2[i] = ctl_data.zs_columns[i].columns[0].len();
        ctl_data_columns_constant_f_cursor[i] = ctl_data_columns_constant_f.len();
        for ci in 0..each_ctl_vars_columns_dim1[i] {
            for cj in 0..each_ctl_vars_columns_dim2[i] {
                let c = &ctl_data.zs_columns[i].columns[ci][cj];
                // next
                assert!(
                    c.next_row_linear_combination.len() == 0,
                    "ctl_data'columns next must empty!"
                );
                // constant
                ctl_data_columns_constant_f.push(c.constant);
                // linear
                ctl_data_columns_linear_f_cursor.push(ctl_data_columns_linear_f.len());
                ctl_data_columns_linear_f_len.push(c.linear_combination.len());
                for tp in &c.linear_combination {
                    ctl_data_columns_linear_i.push(tp.0);
                    ctl_data_columns_linear_f.push(tp.1);
                }
            }
        }
        assert!(ctl_data.zs_columns[i].filter.len() == each_ctl_vars_columns_dim1[i]);
        ctl_data_filter_constant_f_cursor[i] = ctl_data_filter_constant_f.len();
        for filt in &ctl_data.zs_columns[i].filter {
            assert!(filt.is_some());
            assert!(filt.as_ref().unwrap().products.len() == 0);
            assert!(filt.as_ref().unwrap().constants.len() == 1);
            let c = &filt.as_ref().unwrap().constants[0];
            // next
            assert!(
                c.next_row_linear_combination.len() == 0,
                "ctl_data'filter next must empty!"
            );
            // constant
            ctl_data_filter_constant_f.push(c.constant);
            // linear
            ctl_data_filter_linear_f_cursor.push(ctl_data_filter_linear_f.len());
            ctl_data_filter_linear_f_len.push(c.linear_combination.len());
            for tp in &c.linear_combination {
                ctl_data_filter_linear_i.push(tp.0);
                ctl_data_filter_linear_f.push(tp.1);
            }
        }
    }

    let ctl_data_challenges_beta_gamma_gf: *mut GoldilocksField = unsafe
        { transmute(&mut ctl_data_challenges_beta_gamma[0]) };
    let ctl_data_columns_linear_gf: *mut GoldilocksField = unsafe { transmute(&mut ctl_data_columns_linear_f[0]) };
    let ctl_data_columns_constant_gf: *mut GoldilocksField = unsafe { transmute(&mut ctl_data_columns_constant_f[0]) };
    let ctl_data_filter_linear_gf: *mut GoldilocksField = unsafe { transmute(&mut ctl_data_filter_linear_f[0]) };
    let ctl_data_filter_constant_gf: *mut GoldilocksField = unsafe { transmute(&mut ctl_data_filter_constant_f[0]) };
    timing.pop();

    timing.push("1 compute_quotient_polys_cuda_wrap", log::Level::Info);
    let mut constraint_accs_vec: Vec<GoldilocksField> = vec![GoldilocksField::ZERO; (degree << quotient_degree_bits) * alpha_len];
    unsafe {
        compute_quotient_polys_cuda_warp(
            constraint_accs_vec.as_mut_ptr(),
            stark_type,
            degree,
            degree_bits,
            quotient_degree_bits,
            trace_commitment_polynum,
            trace_commitment_polylen,
            trace_commitment_leaves_gf,
            alphas_gf,
            alpha_len,
            ops_streams_vec.as_mut_ptr(),
            ops_streams_len as _,
            // step_2 data
            step2_exec_flag,
            auxiliary_polys_commitment_polynum,
            auxiliary_polys_commitment_polylen,
            auxiliary_polys_commitment_leaves_gf,
            lookups_columns_len,
            lookups_columns_linear_idx.as_mut_ptr(),
            lookups_columns_linear_gf,
            lookup_vars_lookup_challenges_len,
            lookup_vars_lookup_challenges_gf,
            num_lookup_columns,
            // step_3 data
            ctl_data_len,
            num_ctl_columns.as_ptr(),
            each_ctl_vars_columns_dim1.as_ptr(),
            each_ctl_vars_columns_dim2.as_ptr(),
            ctl_data_challenges_beta_gamma_gf,
            ctl_data_columns_constant_f.len(),
            ctl_data_columns_constant_gf, //总⻓度 sum_i(each_ctl_vars_columns_dim1[i] * each_ctl_vars_columns_dim2[i])
            ctl_data_columns_constant_f_cursor.as_ptr(), // vec![0; ctl_data_len];
            ctl_data_columns_linear_f.len(),
            ctl_data_columns_linear_i.as_ptr(),
            ctl_data_columns_linear_gf,
            ctl_data_columns_linear_f_len.as_ptr(), //⻓度与 ctl_data_columns_constant_f 相同
            ctl_data_columns_linear_f_cursor.as_ptr(), //⻓度与 ctl_data_columns_constant_f 相同
            ctl_data_filter_constant_f.len(),
            ctl_data_filter_constant_gf,
            ctl_data_filter_constant_f_cursor.as_ptr(),
            ctl_data_filter_linear_f.len(),
            ctl_data_filter_linear_i.as_ptr(),
            ctl_data_filter_linear_gf,
            ctl_data_filter_linear_f_len.as_ptr(), //⻓度与 ctl_data_filter_constant_f 相同
            ctl_data_filter_linear_f_cursor.as_ptr(), //⻓度与 ctl_data_filter_constant_f 相同
            timing,
        );
    }
    timing.pop();
    timing.push("2 compute result back_to_Field", log::Level::Info);
    let constraint_accs_vec_f: *mut F = unsafe { transmute(&mut constraint_accs_vec[0]) };
    let mut vec_of_result_f: Vec<PolynomialCoeffs<F>> = Vec::with_capacity(alpha_len); // 创建一个容量为2的 Vec
    unsafe {
        for i in 0..alpha_len {
            let start: isize = (i << (degree_bits + quotient_degree_bits)) as isize; // 计算每个向量的起始索引
            let slice = std::slice::from_raw_parts(constraint_accs_vec_f.
                offset(start), 1 << (degree_bits + quotient_degree_bits));
            vec_of_result_f.push(PolynomialCoeffs::new(slice.to_vec()));
            // 将切片转换为 Vec 并推入
        }
    }
    timing.pop();
    vec_of_result_f
}
