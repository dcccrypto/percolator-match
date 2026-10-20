//! v22kani 2026-10-20, agent MS, gap G3: matcher PRODUCTION pricing bounds (cfg(kani) only).
//!
//! The audit's K-M1/M2/M4/M5 (`kani_audit_1017.rs`) state the price bound as
//! `p*1e4 <= o*(1e4+max_total) + 9999`, which makes the solver prove multiplication
//! monotonicity (`o*(1e4+t) <= o*(1e4+m)`) at a 50..64-bit multiplicand: no verdict in 2400 s,
//! and z3 crashes CBMC on this crate. Split here:
//!  * STRUCTURAL (this file, full u64 oracle, any i128 request, REAL `compute_execution_units`):
//!    `u128::checked_mul` is replaced by a RECORDING stub that returns ANY `Option<u128>` (a
//!    superset of every real result, so every assertion below holds for the real multiply too)
//!    and logs its operands and result. The harness then asserts the exact operand range of the
//!    pricing multiply (`oracle * (1e4 +- t)` with `base+fee <= t <= max_total`) and the exact
//!    ceil (ask) / floor (bid) relation between the returned price and that product. No harness
//!    multiplier except by the constant 10 000.
//!  * ARITHMETIC (z3 over unbounded Int, `kani/int-lemmas/matcher_price.py`, not Kani): with the
//!    real `checked_mul` returning `Some(o*b)` exactly, these facts imply the K-M1/M2 price
//!    assertions verbatim (`p >= o`, `p*1e4 <= o*(1e4+m)+9999`; bid mirror).
use super::*;

static mut MUL_LOG: [(u128, u128, Option<u128>); 4] = [(0, 0, None); 4];
static mut MUL_N: usize = 0;
static mut SKEW_SEEN: u128 = 0;

/// Recording over-approximation of `u128::checked_mul`: any result, operands and result logged.
fn checked_mul_rec(a: u128, b: u128) -> Option<u128> {
    let r: Option<u128> = kani::any();
    unsafe {
        let k = MUL_N;
        assert!(k < 4, "at most 4 u128 multiplies on one pricing path");
        MUL_LOG[k] = (a, b, r);
        MUL_N = k + 1;
    }
    r
}

/// Any skew surcharge in [0, 5000] (K-M3 proves the REAL `compute_skew_extra_bps_units` lies in
/// this range), recorded so a cover can see whether the vAMM impact moved the price.
fn skew_rec(_ctx: &MatcherCtx, _is_buy: bool, _v3_units: bool) -> u128 {
    let x: u128 = kani::any();
    kani::assume(x <= 5000);
    unsafe {
        SKEW_SEEN = x;
    }
    x
}

fn any_ctx(kind: u8) -> MatcherCtx {
    MatcherCtx {
        magic: MATCHER_MAGIC,
        version: MATCHER_VERSION,
        kind,
        _pad0: [0; 3],
        lp_pda: [1; 32],
        trading_fee_bps: kani::any(),
        base_spread_bps: kani::any(),
        max_total_bps: kani::any(),
        impact_k_bps: kani::any(),
        liquidity_notional_e6: kani::any(),
        max_fill_abs: kani::any(),
        inventory_base: kani::any(),
        last_oracle_price_e6: 0,
        last_exec_price_e6: 0,
        max_inventory_abs: kani::any(),
        insurance_accrued_e6: 0,
        fee_to_insurance_bps: 0,
        skew_spread_mult_bps: kani::any(),
        _new_pad: [0; 4],
        lp_account_id: 0,
        insurance_fee_remainder_e6: 0,
        backing_fee_cap_bps: 0,
        _reserved: [0; 78],
    }
}

fn check_exec_structural(kind: u8) {
    let ctx = any_ctx(kind);
    kani::assume(ctx.validate().is_ok());
    let oracle: u64 = kani::any();
    let req: i128 = kani::any();
    let call = MatcherCall { req_id: 1, asset_index: 0, lp_account_id: 0, oracle_price_e6: oracle, req_size: req };
    let v3: bool = kani::any();
    let inv_ok = ctx.max_inventory_abs == 0 || ctx.inventory_base.unsigned_abs() <= ctx.max_inventory_abs;
    unsafe {
        MUL_N = 0;
    }
    let res = compute_execution_units(&ctx, &call, v3);
    let (log, n, skew) = unsafe { (MUL_LOG, MUL_N, SKEW_SEEN) };
    let vamm = kind == MatcherKind::Vamm as u8;
    match res {
        Err(e) => {
            assert!(e == ProgramError::ArithmeticOverflow, "the only error on a validated Passive/Vamm ctx");
            kani::cover!(true, "error path reached");
        }
        Ok((price, size, flags)) => {
            let req_abs = req.unsigned_abs();
            let fill = size.unsigned_abs();
            assert!(flags & FLAG_VALID != 0);
            assert!(fill <= req_abs, "never fills more than asked");
            assert!(fill <= ctx.max_fill_abs, "never fills more than the per-call cap");
            assert!(size == 0 || (size > 0) == (req > 0), "sign follows the request");
            if fill < req_abs {
                assert!(flags & FLAG_PARTIAL_OK != 0, "a clipped fill is flagged partial (GH#452)");
            }
            if size == 0 {
                assert!(price == oracle);
                assert!(n == 0, "a zero fill is not priced");
                kani::cover!(req != 0, "zero fill of a non-zero request");
            } else {
                // ---- pricing structure ----
                assert!(n == if vamm { 3 } else { 1 }, "passive: one multiply; vamm: notional, impact, price");
                if vamm {
                    assert!(log[0].0 == fill && log[0].1 == oracle as u128, "notional = fill * oracle");
                }
                let (a, b, x) = log[n - 1];
                assert!(a == oracle as u128, "price multiply is oracle * (1e4 +- t)");
                assert!(x.is_some(), "an Ok price comes from a non-overflowing product");
                let x = x.unwrap_or(0);
                let m = ctx.max_total_bps as u128;
                let bf = ctx.base_spread_bps as u128 + ctx.trading_fee_bps as u128;
                let p = price as u128;
                if size > 0 {
                    assert!(b >= 10_000 + bf && b <= 10_000 + m, "ask spread t in [base+fee, max_total]");
                    assert!(p * 10_000 >= x, "ask rounded UP (toward the LP)");
                    assert!(x.checked_add(9_999).is_some_and(|y| p * 10_000 <= y), "ask is the exact ceiling");
                    kani::cover!(p * 10_000 > x, "ask strictly rounded up");
                    kani::cover!(b == 10_000 + m && m > bf, "ask at the max_total cap");
                    kani::cover!(b > 10_000 + bf && b < 10_000 + m, "ask strictly inside the band");
                    if vamm {
                        kani::cover!(b > 10_000 + bf + skew && b < 10_000 + m, "vamm impact moved the ask (unclamped)");
                    }
                } else {
                    assert!(b <= 10_000 - bf && b >= 10_000 - m, "bid spread t in [base+fee, max_total]");
                    assert!(p * 10_000 <= x, "bid rounded DOWN (toward the LP)");
                    assert!(p * 10_000 + 9_999 >= x, "bid is the exact floor");
                    assert!(p >= 1, "zero bid refused");
                    kani::cover!(b < 10_000 && p * 10_000 < x, "bid strictly below, rounded down");
                    kani::cover!(b == 10_000 - m && m > bf, "bid at the max_total cap");
                }
                if fill < req_abs {
                    kani::cover!(ctx.max_fill_abs < req_abs, "clipped by max_fill_abs");
                    kani::cover!(ctx.max_inventory_abs != 0 && ctx.max_fill_abs >= req_abs, "clipped by the inventory cap");
                }
                if ctx.max_inventory_abs != 0 && inv_ok {
                    let new_inv = ctx.inventory_base.checked_sub(size);
                    assert!(new_inv.is_some_and(|v| v.unsigned_abs() <= ctx.max_inventory_abs), "inventory stays in the cap");
                    kani::cover!(true, "inventory-capped fill ended within the cap");
                }
            }
        }
    }
}

/// MS-M1n: production Passive pricing: fill, flags, inventory cap, and the exact ceil/floor pricing
/// structure with `base+fee <= t <= max_total`, full u64 oracle.
#[kani::proof]
#[kani::unwind(81)]
#[kani::stub(u128::checked_mul, checked_mul_rec)]
#[kani::stub(super::compute_skew_extra_bps_units, skew_rec)]
fn ms_m1n_passive_exec_bounds_structural() {
    check_exec_structural(MatcherKind::Passive as u8);
}

/// MS-M2n: same for the vAMM (impact clamped by max_total).
#[kani::proof]
#[kani::unwind(81)]
#[kani::stub(u128::checked_mul, checked_mul_rec)]
#[kani::stub(super::compute_skew_extra_bps_units, skew_rec)]
fn ms_m2n_vamm_exec_bounds_structural() {
    check_exec_structural(MatcherKind::Vamm as u8);
}

/// MS-IMP (rewrite of the VACUOUS `proof_impact_bps_no_overflow`, which asserted `x <= u128::MAX`
/// on a copy of the formula): in the domain that proof documents (oracle <= 1e12, fill <= 1e18,
/// impact_k <= 9000, liquidity >= 1) the REAL vAMM path, with REAL multiplies, never raises
/// ArithmeticOverflow and always fills in full, whatever the impact. Oracle >= 10 keeps the bid
/// above 0 (o * (1e4 - 9000) >= 1e4).
#[kani::proof]
#[kani::unwind(81)]
#[kani::stub(super::compute_skew_extra_bps_units, skew_rec)]
fn ms_imp_vamm_impact_never_overflows_in_documented_domain() {
    let mut ctx = any_ctx(MatcherKind::Vamm as u8);
    ctx.max_inventory_abs = 0;
    kani::assume(ctx.validate().is_ok());
    kani::assume(ctx.impact_k_bps <= 9000);
    let oracle: u64 = kani::any();
    kani::assume(oracle >= 10 && oracle <= 1_000_000_000_000);
    kani::assume(oracle >> 40 == 0); // implied by oracle <= 1e12 < 2^40 (solver hint, no domain change)
    let req: i128 = kani::any();
    let req_abs = req.unsigned_abs();
    kani::assume(req != 0 && req_abs <= 1_000_000_000_000_000_000);
    kani::assume(req_abs >> 60 == 0); // implied by 1e18 < 2^60
    kani::assume(ctx.max_fill_abs >= req_abs);
    let call = MatcherCall { req_id: 1, asset_index: 0, lp_account_id: 0, oracle_price_e6: oracle, req_size: req };
    let v3: bool = kani::any();
    let r = compute_execution_units(&ctx, &call, v3);
    assert!(r.is_ok(), "no ArithmeticOverflow anywhere on the vAMM path in the documented domain");
    if let Ok((price, size, _)) = r {
        assert!(size == req, "full fill (no cap)");
        // impact >= max_total for sure: liq == 1, k >= 1, notional >= 9e9 * 10 / 1e6 = 9e4 > 9000 bps
        let big_impact = ctx.liquidity_notional_e6 == 1 && ctx.impact_k_bps >= 1 && req_abs >= 9_000_000_000;
        kani::cover!(req > 0 && price as u128 > oracle as u128, "buy priced");
        kani::cover!(req < 0 && (price as u128) < oracle as u128, "sell priced");
        kani::cover!(big_impact && ctx.max_total_bps > 0, "impact at/over the max_total budget (clamp binds)");
    }
}
