//! Kani push 2026-09-30 (Anvil, formal-verification lane) — P2 matcher v2.
//!
//! Complements the builder's `v2::proofs::*`. Those prove the pure pieces (fee bounds, CP
//! impact, skew term). These prove:
//!  - the stale-mark gate on the REAL leg executor (`vamm::execute_leg`), not just the
//!    `mark_state` predicate;
//!  - the composed quote (`v2::quote_adaptive`) is monotone in the EXECUTED size (price and
//!    total spread), and does not fail (None -> ArithmeticOverflow revert) inside the
//!    documented input domain.
//!
//! Every harness declares covers; SUCCESSFUL counts only with every cover SATISFIED.
//! Run locally only:  cargo kani --tests --harness kani_push_p2
#![cfg(kani)]

extern crate kani;

use percolator_match::v2::{self, AdaptiveQuoteIn, CallExt, V2Block, V2Config, V2State};
use percolator_match::vamm::{execute_leg, MatcherCtx, MatcherKind};
use percolator_match::MatcherCall;

fn any_quote_small() -> AdaptiveQuoteIn {
    let q = AdaptiveQuoteIn {
        oracle_e6: kani::any(),
        fill: kani::any(),
        taker_buys: kani::any(),
        inv_pre: kani::any(),
        base_spread_bps: kani::any(),
        max_total_bps: kani::any(),
        fee_bps: kani::any(),
        impact_k_bps: kani::any(),
        depth_e6: kani::any(),
        s_mult_bps: kani::any(),
        r_mult_bps: kani::any(),
        skew_cap_bps: kani::any(),
        rebate_cap_bps: kani::any(),
        ref_inv: kani::any(),
    };
    // The builder's own domain (v2::proofs::any_quote), narrowed on the size-like fields to
    // keep two symbolic quotes tractable.
    kani::assume(q.oracle_e6 >= 1 && q.oracle_e6 <= 1_000_000_000_000);
    kani::assume(q.fill < (1u128 << 32));
    kani::assume(q.inv_pre > -(1i128 << 32) && q.inv_pre < (1i128 << 32));
    kani::assume(q.max_total_bps <= 9_000 && q.base_spread_bps <= 9_000);
    kani::assume(q.fee_bps <= v2::MAX_FEE_BPS as u128);
    kani::assume(q.impact_k_bps <= v2::MAX_IMPACT_K_BPS);
    kani::assume(q.depth_e6 < (1u128 << 48));
    kani::assume(q.s_mult_bps <= 10_000 && q.r_mult_bps <= q.s_mult_bps);
    kani::assume(q.skew_cap_bps <= v2::MAX_SKEW_CAP_BPS && q.rebate_cap_bps <= q.skew_cap_bps);
    kani::assume(q.ref_inv > 0 && q.ref_inv < (1u64 << 32));
    q
}

/// MONOTONE IN SIZE. Same market state, two requests. Whenever the executed fill of A is <=
/// that of B, A's total spread is <= B's and A's price is no worse for the taker than B's
/// (buy: lower or equal; sell: higher or equal). So no taker can get a better average price
/// by asking for more, and splitting a fill into pieces cannot beat one fill.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_push_p2_quote_monotone_in_executed_size() {
    let a = any_quote_small();
    let fill_b: u128 = kani::any();
    kani::assume(fill_b < (1u128 << 32));
    let b = AdaptiveQuoteIn { fill: fill_b, ..a };
    let (Some((fa, pa, ta)), Some((fb, pb, tb))) = (v2::quote_adaptive(&a), v2::quote_adaptive(&b))
    else {
        return;
    };
    if fa > 0 && fb > 0 && fa <= fb {
        assert!(ta <= tb);
        if a.taker_buys {
            assert!(pa <= pb);
        } else {
            assert!(pa >= pb);
        }
        kani::cover!(fa < fb && ta < tb, "strictly more expensive for a larger fill");
        kani::cover!(fa < fb && a.inv_pre != 0, "monotone off a skewed book");
    }
}

/// MONOTONE IN SKEW. Same request against a book already more crowded in the taker's
/// direction (LP inventory further on the side the fill pushes it) never gets a cheaper
/// total spread, for any executed fill that is not size-clipped.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_push_p2_quote_monotone_in_skew() {
    let a = any_quote_small();
    let more: i128 = kani::any();
    kani::assume(more >= 0 && more < (1i128 << 31));
    // taker buys => LP sells => inventory goes DOWN; more crowded = lower inventory.
    let inv_b = if a.taker_buys { a.inv_pre - more } else { a.inv_pre + more };
    kani::assume(inv_b > -(1i128 << 32) && inv_b < (1i128 << 32));
    let b = AdaptiveQuoteIn { inv_pre: inv_b, ..a };
    let (Some((fa, _pa, ta)), Some((fb, _pb, tb))) = (v2::quote_adaptive(&a), v2::quote_adaptive(&b))
    else {
        return;
    };
    if fa == a.fill && fb == b.fill && fa > 0 {
        assert!(ta <= tb);
        kani::cover!(ta < tb, "crowded book strictly dearer");
    }
}

/// NO OVERFLOW / NO SPURIOUS REVERT inside the documented domain: `quote_adaptive` returns
/// Some (execute_leg maps None to ArithmeticOverflow, i.e. the taker's tx reverts). The
/// builder's `proof_quote_never_crosses_oracle` doc claims this but its body is inside
/// `if let Some(..)`, so it never checks it.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_push_p2_quote_never_none_in_domain() {
    let q = any_quote_small();
    let r = v2::quote_adaptive(&q);
    assert!(r.is_some());
    kani::cover!(matches!(r, Some((f, _, _)) if f > 0), "non-zero fill");
}

// ── stale mark on the real executor ────────────────────────────────────────────────────────

fn ctx_with_block(kind: MatcherKind, cfg: V2Config, st: V2State) -> MatcherCtx {
    let mut ctx = MatcherCtx::default();
    ctx.kind = kind as u8;
    ctx.trading_fee_bps = kani::any();
    ctx.base_spread_bps = kani::any();
    ctx.max_total_bps = kani::any();
    ctx.impact_k_bps = kani::any();
    ctx.liquidity_notional_e6 = kani::any();
    ctx.max_fill_abs = kani::any();
    ctx.inventory_base = kani::any();
    ctx.max_inventory_abs = kani::any();
    ctx.skew_spread_mult_bps = kani::any();
    kani::assume(ctx.trading_fee_bps <= 1_000 && ctx.base_spread_bps <= 9_000);
    kani::assume(ctx.max_total_bps <= 9_000 && ctx.impact_k_bps <= 100_000);
    kani::assume(ctx.liquidity_notional_e6 < (1u128 << 48));
    kani::assume(ctx.max_fill_abs < (1u128 << 32) && ctx.max_inventory_abs < (1u128 << 33));
    kani::assume(ctx.inventory_base.unsigned_abs() <= ctx.max_inventory_abs);
    ctx.set_v2_block(&V2Block { cfg, st });
    ctx
}

fn stale_setup() -> (V2Config, V2State, u64, u64) {
    let mut cfg = V2Config::default();
    cfg.flags = kani::any();
    cfg.max_mark_age_slots = kani::any();
    cfg.observed_stale_slots = 0; // authoritative mark_slot path only (observed path: builder)
    cfg.fee_lo_bps = 30;
    cfg.fee_hi_bps = 150;
    cfg.fee_cold_bps = 80;
    cfg.skew_ref_inventory = 1_000_000;
    let mut st = V2State::default();
    st.vol_warmup_left = 1; // cold fee: keeps the isqrt estimator out of the solver
    let now: u64 = kani::any();
    let ms: u64 = kani::any();
    kani::assume(cfg.max_mark_age_slots > 0);
    kani::assume(ms <= now && now - ms > cfg.max_mark_age_slots as u64);
    (cfg, st, now, ms)
}

/// NEVER PRICES ON A STALE MARK (documented semantics, ABI doc §MARK_SLOT). For a ctx with a
/// v2 block and `max_mark_age_slots > 0`, if the wrapper's `mark_slot` is older than the limit
/// then `execute_leg` either refuses, or returns a ZERO fill, or — only with the ctx flag
/// STALE_ALLOW_REDUCING — fills a trade that (a) the wrapper attested as the taker's own exit,
/// or (b) reduces the LP's inventory by at most |inventory| (cannot flip it).
fn check_stale(kind: MatcherKind) {
    let (cfg, st, now, ms) = stale_setup();
    let mut ctx = ctx_with_block(kind, cfg, st);
    let inv = ctx.inventory_base;
    let call = MatcherCall {
        req_id: 1,
        asset_index: 0,
        lp_account_id: 0,
        oracle_price_e6: kani::any(),
        req_size: kani::any(),
    };
    kani::assume(call.oracle_price_e6 >= 1 && call.oracle_price_e6 <= 1_000_000_000_000);
    kani::assume(call.req_size != 0 && call.req_size.unsigned_abs() < (1u128 << 32));
    let ext = CallExt {
        headroom_q: None,
        mark_slot: Some(ms),
        accepts_fee_request: false,
        taker_reducing: kani::any(),
        exec_band_bps: None,
    };
    let r = execute_leg(&mut ctx, &call, &ext, Some(now), 0);
    let allow = cfg.flags & v2::V2_FLAG_STALE_ALLOW_REDUCING != 0;
    if let Ok(out) = r {
        if out.exec_size != 0 {
            assert!(allow);
            if !ext.taker_reducing {
                // LP takes the opposite side: taker buys => LP inventory falls.
                let lp_after = inv - out.exec_size;
                assert!(lp_after.unsigned_abs() <= inv.unsigned_abs());
                assert!(lp_after == 0 || (lp_after > 0) == (inv > 0));
                kani::cover!(lp_after.unsigned_abs() < inv.unsigned_abs(), "stale, LP-reducing fill");
            } else {
                kani::cover!(true, "stale, wrapper-attested taker exit");
            }
        }
    } else {
        kani::cover!(!allow, "stale refused");
    }
}

#[kani::proof]
#[kani::solver(kissat)]
#[kani::unwind(34)]
fn kani_push_p2_stale_mark_never_prices_adaptive() {
    check_stale(MatcherKind::Adaptive);
}

#[kani::proof]
#[kani::solver(kissat)]
#[kani::unwind(34)]
fn kani_push_p2_stale_mark_never_prices_passive_with_block() {
    check_stale(MatcherKind::Passive);
}
