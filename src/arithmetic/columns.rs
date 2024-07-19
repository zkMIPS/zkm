//! Arithmetic unit

use std::ops::Range;

pub const LIMB_BITS: usize = 16;
const ZKM_REGISTER_BITS: usize = 32;

/// Return the number of LIMB_BITS limbs that are in an MIPS
/// register-sized number, panicking if LIMB_BITS doesn't divide in
/// the MIPS register size.
const fn n_limbs() -> usize {
    if ZKM_REGISTER_BITS % LIMB_BITS != 0 {
        panic!("limb size must divide MIPS register size");
    }
    let n = ZKM_REGISTER_BITS / LIMB_BITS;
    if n % 2 == 1 {
        panic!("number of limbs must be even");
    }
    n
}

/// Number of LIMB_BITS limbs that are in on MIPS register-sized number.
pub const N_LIMBS: usize = n_limbs();

pub(crate) const IS_ADD: usize = 0;
pub(crate) const IS_ADDU: usize = IS_ADD + 1;
pub(crate) const IS_ADDI: usize = IS_ADDU + 1;
pub(crate) const IS_ADDIU: usize = IS_ADDI + 1;
pub(crate) const IS_SUB: usize = IS_ADDIU + 1;
pub(crate) const IS_SUBU: usize = IS_SUB + 1;
pub(crate) const IS_MULT: usize = IS_SUBU + 1;
pub(crate) const IS_MULTU: usize = IS_MULT + 1;
pub(crate) const IS_MUL: usize = IS_MULTU + 1;
pub(crate) const IS_DIV: usize = IS_MUL + 1;
pub(crate) const IS_DIVU: usize = IS_DIV + 1;
pub(crate) const IS_SLLV: usize = IS_DIVU + 1;
pub(crate) const IS_SRLV: usize = IS_SLLV + 1;
pub(crate) const IS_SRAV: usize = IS_SRLV + 1;
pub(crate) const IS_SLL: usize = IS_SRAV + 1;
pub(crate) const IS_SRL: usize = IS_SLL + 1;
pub(crate) const IS_SRA: usize = IS_SRL + 1;
pub(crate) const IS_SLT: usize = IS_SRA + 1;
pub(crate) const IS_SLTU: usize = IS_SLT + 1;
pub(crate) const IS_SLTI: usize = IS_SLTU + 1;
pub(crate) const IS_SLTIU: usize = IS_SLTI + 1;
pub(crate) const IS_LUI: usize = IS_SLTIU + 1;
pub(crate) const IS_MFHI: usize = IS_LUI + 1;
pub(crate) const IS_MTHI: usize = IS_MFHI + 1;
pub(crate) const IS_MFLO: usize = IS_MTHI + 1;
pub(crate) const IS_MTLO: usize = IS_MFLO + 1;

pub(crate) const START_SHARED_COLS: usize = IS_MTLO + 1;

/// Within the Arithmetic Unit, there are shared columns which can be
/// used by any arithmetic circuit, depending on which one is active
/// this cycle.
///
/// Modular arithmetic takes 11 * N_LIMBS columns which is split across
/// two rows, the first with 6 * N_LIMBS columns and the second with
/// 5 * N_LIMBS columns. (There are hence N_LIMBS "wasted columns" in
/// the second row.)
pub(crate) const NUM_SHARED_COLS: usize = 9 * N_LIMBS;
pub(crate) const SHARED_COLS: Range<usize> = START_SHARED_COLS..START_SHARED_COLS + NUM_SHARED_COLS;

pub(crate) const INPUT_REGISTER_0: Range<usize> = START_SHARED_COLS..START_SHARED_COLS + N_LIMBS;
pub(crate) const INPUT_REGISTER_1: Range<usize> =
    INPUT_REGISTER_0.end..INPUT_REGISTER_0.end + N_LIMBS;
pub(crate) const INPUT_REGISTER_2: Range<usize> =
    INPUT_REGISTER_1.end..INPUT_REGISTER_1.end + N_LIMBS;
pub(crate) const OUTPUT_REGISTER: Range<usize> =
    INPUT_REGISTER_2.end..INPUT_REGISTER_2.end + N_LIMBS;

// NB: Only one of AUX_INPUT_REGISTER_[01] or AUX_INPUT_REGISTER_DBL
// will be used for a given operation since they overlap
pub(crate) const AUX_INPUT_REGISTER_0: Range<usize> =
    OUTPUT_REGISTER.end..OUTPUT_REGISTER.end + N_LIMBS;
pub(crate) const AUX_INPUT_REGISTER_1: Range<usize> =
    AUX_INPUT_REGISTER_0.end..AUX_INPUT_REGISTER_0.end + N_LIMBS;
pub(crate) const AUX_INPUT_REGISTER_DBL: Range<usize> =
    OUTPUT_REGISTER.end..OUTPUT_REGISTER.end + 2 * N_LIMBS;
pub(crate) const AUX_INPUT_REGISTER_2: Range<usize> =
    AUX_INPUT_REGISTER_1.end..AUX_INPUT_REGISTER_1.end + N_LIMBS;

// The auxiliary input columns overlap the general input columns
// because they correspond to the values in the second row for modular
// operations.
const AUX_REGISTER_0: Range<usize> = START_SHARED_COLS..START_SHARED_COLS + N_LIMBS;
const AUX_REGISTER_1: Range<usize> = AUX_REGISTER_0.end..AUX_REGISTER_0.end + 2 * N_LIMBS;
const AUX_REGISTER_2: Range<usize> = AUX_REGISTER_1.end..AUX_REGISTER_1.end + 2 * N_LIMBS - 1;

// Each element c of {MUL,MODULAR}_AUX_REGISTER is -2^20 <= c <= 2^20;
// this value is used as an offset so that everything is positive in
// the range checks.
pub(crate) const AUX_COEFF_ABS_MAX: i64 = 1 << 20;

pub(crate) const MUL_AUX_INPUT_LO: Range<usize> = AUX_INPUT_REGISTER_0;
pub(crate) const MUL_AUX_INPUT_HI: Range<usize> = AUX_INPUT_REGISTER_1;

pub(crate) const MODULAR_INPUT_0: Range<usize> = INPUT_REGISTER_0;
pub(crate) const MODULAR_INPUT_1: Range<usize> = INPUT_REGISTER_1;
pub(crate) const MODULAR_MODULUS: Range<usize> = INPUT_REGISTER_2;
pub(crate) const MODULAR_OUTPUT: Range<usize> = OUTPUT_REGISTER;
pub(crate) const MODULAR_QUO_INPUT: Range<usize> = AUX_INPUT_REGISTER_DBL;
pub(crate) const MODULAR_OUT_AUX_RED: Range<usize> = AUX_REGISTER_0;
// NB: Last value is not used in AUX, it is used in MOD_IS_ZERO
pub(crate) const MODULAR_MOD_IS_ZERO: usize = AUX_REGISTER_1.start;
pub(crate) const MODULAR_AUX_INPUT_LO: Range<usize> = AUX_REGISTER_1.start + 1..AUX_REGISTER_1.end;
pub(crate) const MODULAR_AUX_INPUT_HI: Range<usize> = AUX_REGISTER_2;
// Must be set to MOD_IS_ZERO for DIV and SHR operations i.e. MOD_IS_ZERO * (lv[IS_DIV] + lv[IS_SHR]).
pub(crate) const MODULAR_DIV_DENOM_IS_ZERO: usize = AUX_REGISTER_2.end;

/// The counter column (used for the range check) starts from 0 and increments.
pub(crate) const RANGE_COUNTER: usize = START_SHARED_COLS + NUM_SHARED_COLS;
/// The frequencies column used in logUp.
pub(crate) const RC_FREQUENCIES: usize = RANGE_COUNTER + 1;
// These counter columns only used in SRA(V) and DIV, and do not check range
pub(crate) const AUX_EXTRA: Range<usize> = RC_FREQUENCIES + 1..RC_FREQUENCIES + 9;

pub const NUM_ARITH_COLUMNS: usize = START_SHARED_COLS + NUM_SHARED_COLS + 10;

// These counters are only be used in mul and div that use LO and HI.
pub(crate) const OUTPUT_REGISTER_LO: Range<usize> = OUTPUT_REGISTER;
pub(crate) const OUTPUT_REGISTER_HI: Range<usize> =
    OUTPUT_REGISTER.end..OUTPUT_REGISTER.end + N_LIMBS;
pub(crate) const MULT_AUX_LO: Range<usize> =
    OUTPUT_REGISTER_HI.end..OUTPUT_REGISTER_HI.end + 2 * N_LIMBS;
pub(crate) const MULT_AUX_HI: Range<usize> = MULT_AUX_LO.end..MULT_AUX_LO.end + 2 * N_LIMBS;
