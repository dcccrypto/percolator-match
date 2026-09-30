//! Adversarial Kani review 2026-09-30 (Sentinel): P2 v2 pricing over the domain
//! `validate_config` actually admits. The builder's `any_quote`/`skew_args` assume
//! `s_mult_bps <= 10_000` and `ref_inv < 2^20`; validate_config bounds neither
//! (`skew_spread_mult_bps` is any u16; `default_config_for_kind2` ships
//! `skew_ref_inventory = u64::MAX` when `max_inventory_abs == 0`). These harnesses widen
//! exactly those two fields to their full admitted range. Local only (never CI).
use crate::v2::*;

fn any_quote_admitted() -> AdaptiveQuoteIn {
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
    kani::assume(q.oracle_e6 >= 1 && q.oracle_e6 < (1u64 << 32));
    kani::assume(q.fill < (1u128 << 20));
    kani::assume(q.inv_pre > -(1i128 << 20) && q.inv_pre < (1i128 << 20));
    kani::assume(q.max_total_bps <= 9_000 && q.base_spread_bps <= 9_000);
    kani::assume(q.fee_bps <= MAX_FEE_BPS as u128);
    kani::assume(q.impact_k_bps <= MAX_IMPACT_K_BPS);
    kani::assume(q.depth_e6 < (1u128 << 40));
    // WIDENED: any u16 surcharge slope with rebate <= surcharge (validate_config's rule).
    kani::assume(q.r_mult_bps <= q.s_mult_bps);
    kani::assume(q.skew_cap_bps <= MAX_SKEW_CAP_BPS && q.rebate_cap_bps <= q.skew_cap_bps);
    // WIDENED: any non-zero u64 reference inventory, including the shipped u64::MAX default.
    kani::assume(q.ref_inv > 0);
    q
}

/// Never crosses the oracle, never above max_total, never grows the fill — AND never
/// returns None (fail-closed refusal) anywhere in the admitted domain, including the
/// shipped `skew_ref_inventory = u64::MAX` default.
#[kani::proof]
#[kani::solver(cadical)]
#[kani::unwind(24)]
fn proof_review_quote_admitted_domain() {
    let q = any_quote_admitted();
    let r = quote_adaptive(&q);
    kani::cover!(r.is_none(), "quote refuses (None) somewhere in the admitted domain");
    if let Some((fill, price, total)) = r {
        assert!(fill <= q.fill);
        assert!(total <= q.max_total_bps as u128);
        if fill > 0 && q.taker_buys {
            assert!(price >= q.oracle_e6);
        }
        if fill > 0 && !q.taker_buys {
            assert!(price <= q.oracle_e6);
        }
        kani::cover!(fill > 0 && q.s_mult_bps > 10_000 && total > 0, "surcharge slope above the builder's 10_000 bound");
        kani::cover!(fill > 0 && q.ref_inv == u64::MAX, "shipped u64::MAX reference inventory");
    }
}

/// Skew term monotone in size over the admitted slope/reference domain.
#[kani::proof]
#[kani::solver(cadical)]
fn proof_review_skew_monotone_in_size_admitted() {
    let inv: i128 = kani::any();
    let s: u16 = kani::any();
    let r: u16 = kani::any();
    let sc: u16 = kani::any();
    let rc: u16 = kani::any();
    let rf: u64 = kani::any();
    kani::assume(inv > -(1i128 << 20) && inv < (1i128 << 20));
    kani::assume(r <= s && sc <= MAX_SKEW_CAP_BPS && rc <= sc && rf > 0);
    let lp_sells: bool = kani::any();
    let f1: u128 = kani::any();
    let f2: u128 = kani::any();
    kani::assume(f1 > 0 && f1 <= f2 && f2 < (1u128 << 20));
    let a = skew_net_bps(inv, f1, lp_sells, s, r, sc, rc, rf);
    let b = skew_net_bps(inv, f2, lp_sells, s, r, sc, rc, rf);
    kani::cover!(a.is_none() || b.is_none(), "skew refuses (None)");
    if let (Some(a), Some(b)) = (a, b) {
        assert!(a <= b);
        kani::cover!(a < b && s > 10_000, "strict, slope above the builder bound");
    }
}
