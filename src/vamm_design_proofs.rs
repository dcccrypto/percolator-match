//! Kani design 2026-09-30 (Sentinel) — D-P2-07: the REAL kind-0 (passive) and kind-1 (vAMM)
//! execution the relaunch ships (P3 auto-pin pins PIN_MATCHER_KIND = 1). The earlier vamm proofs
//! 1/4/5/7/9/10/11 recompute formulas inline (models); this calls `compute_passive_execution` /
//! `compute_vamm_execution` (vamm.rs:1297 / :1357) on ANY context `validate()` admits.
//! v2.1 port note: 2b08537 added the growth-v19 L-1 `v3_units` parameter; these proofs pass
//! `false` (the legacy skew units they were designed over). They need re-review if the M-1
//! normalised ramp lands (it removes that parameter).
//! Run: cargo kani -Z stubbing --lib --exact --harness vamm::design_proofs::<name>
use super::*;

fn any_valid_ctx() -> MatcherCtx {
    let bytes: [u8; CTX_VAMM_LEN] = kani::any();
    let ctx = MatcherCtx::read_from(&bytes);
    kani::assume(ctx.is_ok());
    let ctx = ctx.unwrap();
    kani::assume(ctx.validate().is_ok()); // the processor refuses any other context
    ctx
}

/// Linear half (D-P2-07a): sizes, side, zero-fill quote, inventory. No price comparison.
fn check_linear(ctx: &MatcherCtx, call: &MatcherCall, r: &Result<(u64, i128, u32), ProgramError>) {
    let Ok((price, size, _flags)) = *r else { return };
    let req = call.req_size;
    assert!(size.unsigned_abs() <= req.unsigned_abs(), "never over-fills the request");
    assert!(size.unsigned_abs() <= ctx.max_fill_abs, "never exceeds max_fill");
    if size == 0 {
        assert_eq!(price, call.oracle_price_e6, "zero fill quotes the oracle");
        return;
    }
    assert_eq!(size > 0, req > 0, "fills the taker's side");
    if ctx.max_inventory_abs > 0 && ctx.inventory_base.unsigned_abs() <= ctx.max_inventory_abs {
        let new_inv = ctx.inventory_base - size; // LP takes the other side
        assert!(new_inv.unsigned_abs() <= ctx.max_inventory_abs, "inventory limit kept");
    }
}

/// Price half (D-P2-07b): never through the oracle in the taker's favour (nonlinear; 1 h cap,
/// fallback L-PRICE).
fn check_price(call: &MatcherCall, r: &Result<(u64, i128, u32), ProgramError>) {
    let Ok((price, size, _flags)) = *r else { return };
    if size == 0 {
        return;
    }
    if call.req_size > 0 {
        assert!(price >= call.oracle_price_e6, "buy never below the oracle");
    } else {
        assert!(price <= call.oracle_price_e6, "sell never above the oracle");
    }
}

fn any_call() -> MatcherCall {
    let call = MatcherCall { req_id: kani::any(), asset_index: kani::any(), lp_account_id: kani::any(), oracle_price_e6: kani::any(), req_size: kani::any() };
    kani::assume(call.req_size != i128::MIN);
    call
}

#[kani::proof]
fn kani_design_p2_07a_vamm_kind1_fill_side_inventory() {
    let ctx = any_valid_ctx();
    let call = any_call();
    let r = compute_vamm_execution(&ctx, &call, false);
    check_linear(&ctx, &call, &r);
    kani::cover!(matches!(r, Ok((_, s, _)) if s != 0 && s.unsigned_abs() < call.req_size.unsigned_abs()), "partial fill");
    kani::cover!(matches!(r, Ok((_, 0, _))) && call.req_size != 0, "zero fill");
    kani::cover!(r.is_err(), "fails closed");
}

#[kani::proof]
#[kani::solver(kissat)]
fn kani_design_p2_07b_vamm_kind1_never_crosses() {
    let ctx = any_valid_ctx();
    let call = any_call();
    let r = compute_vamm_execution(&ctx, &call, false);
    check_price(&call, &r);
    kani::cover!(matches!(r, Ok((p, s, _)) if s > 0 && p > call.oracle_price_e6), "buy priced above oracle");
    kani::cover!(matches!(r, Ok((p, s, _)) if s < 0 && p < call.oracle_price_e6), "sell priced below oracle");
}

#[kani::proof]
fn kani_design_p2_07a_passive_kind0_fill_side_inventory() {
    let ctx = any_valid_ctx();
    let call = any_call();
    let r = compute_passive_execution(&ctx, &call, false);
    check_linear(&ctx, &call, &r);
    kani::cover!(matches!(r, Ok((_, s, _)) if s != 0 && s.unsigned_abs() < call.req_size.unsigned_abs()), "partial fill");
    kani::cover!(matches!(r, Ok((_, 0, _))) && call.req_size != 0, "zero fill");
}

#[kani::proof]
#[kani::solver(kissat)]
fn kani_design_p2_07b_passive_kind0_never_crosses() {
    let ctx = any_valid_ctx();
    let call = any_call();
    let r = compute_passive_execution(&ctx, &call, false);
    check_price(&call, &r);
    kani::cover!(matches!(r, Ok((p, s, _)) if s < 0 && p < call.oracle_price_e6), "sell priced below oracle");
    kani::cover!(matches!(r, Ok((p, s, _)) if s > 0 && p > call.oracle_price_e6), "buy priced above oracle");
}
