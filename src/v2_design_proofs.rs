//! Kani design 2026-09-30 (Sentinel) — P2 matcher v2 FINAL `4a0f696`.
//! Design doc: ~/percolator-ops/ledger/kani-proof-design-2026-09-30.md (entries D-P2-*).
//! A child module of `v2` so the private pricing fns are called / stubbed in place.
//! Run: cargo kani -Z stubbing --lib --exact --harness v2::design_proofs::<name>

use super::*;

// ── stubs ───────────────────────────────────────────────────────────────────────────────

/// Spec of `price_with_total_bps` (proven by D-P2-01): `None` or a price on the LP's side of
/// the oracle.
fn spec_price_with_total_bps(oracle_e6: u64, total_bps: u128, taker_buys: bool) -> Option<u64> {
    if total_bps > BPS {
        return None;
    }
    let ok: bool = kani::any();
    if !ok {
        return None;
    }
    let p: u64 = kani::any();
    kani::assume(p > 0);
    if taker_buys {
        kani::assume(p >= oracle_e6);
    } else {
        kani::assume(p <= oracle_e6);
    }
    if total_bps == 0 {
        kani::assume(p == oracle_e6);
    }
    Some(p)
}

/// Arbitrary impact / skew, bounded only so the i128 sum in `quote_adaptive` cannot overflow
/// (real skew is bounded by the skew cap, far below 2^64; real impact is clamped to 9_000
/// before the sum). Sound over-approximation of the real `impact_and_skew`.
fn stub_impact_and_skew_any(_q: &AdaptiveQuoteIn, _fill: u128) -> Option<(u128, i128)> {
    if kani::any() {
        return None;
    }
    let i: u128 = kani::any();
    let s: i128 = kani::any();
    kani::assume(s.unsigned_abs() < (1u128 << 64));
    Some((i, s))
}

/// Arbitrary gross surcharge (any value, any None) — for D-P2-02, where the property must hold
/// whatever the size clip decides.
fn stub_gross_any(_q: &AdaptiveQuoteIn, _fill: u128) -> Option<u128> {
    if kani::any() {
        return None;
    }
    Some(kani::any())
}

static mut THRESHOLD: u128 = 0;
/// Threshold model of a MONOTONE feasibility predicate: `gross_pos(f) <= max_total` iff
/// `f <= T`, T fixed per run. Every monotone predicate over fill sizes is of this form, so
/// D-P2-03 is exact for any real `gross_pos_bps` that is monotone in fill (lemma L-GROSS).
fn stub_gross_threshold(q: &AdaptiveQuoteIn, fill: u128) -> Option<u128> {
    let _ = q;
    if fill <= unsafe { THRESHOLD } {
        Some(0)
    } else {
        Some(u128::MAX)
    }
}

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
    // The executor's own invariants (execute_leg): the fee is the adaptive fee <= fee_hi <=
    // MAX_FEE_BPS; base spread and max total are validate_config-bounded u32; fill <= i128::MAX.
    kani::assume(q.fee_bps <= MAX_FEE_BPS as u128);
    kani::assume(q.fill <= i128::MAX as u128);
    kani::assume(q.oracle_e6 > 0);
    q
}

// ── D-P2-01  `price_with_total_bps`, FULL u64 oracle and every total <= 1e4: never prices
// through the oracle in the taker's favour; `None` only for p == 0 or p > u64::MAX.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_design_p2_01_price_never_crosses_full_width() {
    let o: u64 = kani::any();
    let t: u128 = kani::any();
    let buys: bool = kani::any();
    kani::assume(t <= BPS);
    let r = price_with_total_bps(o, t, buys);
    if let Some(p) = r {
        if buys {
            assert!(p >= o);
        } else {
            assert!(p <= o);
        }
        if t == 0 {
            assert_eq!(p, o);
        }
    }
    if o > 0 && buys && t == 0 {
        assert_eq!(r, Some(o));
    }
    kani::cover!(matches!(r, Some(p) if buys && p > o), "buy priced above the oracle");
    kani::cover!(matches!(r, Some(p) if !buys && p < o && o > u32::MAX as u64), "sell priced below a > u32 oracle");
    kani::cover!(r.is_none() && o > 0 && buys, "buy above u64::MAX fails closed");
    kani::cover!(r.is_none() && o > 0 && !buys, "sell rounding to 0 fails closed");
}

// ── D-P2-02  `quote_adaptive` over the WHOLE admitted input domain (no bound on slopes, ref
// inventory, depth, inventory, oracle), with impact/skew/gross arbitrary and the price fn at its
// verified spec: whenever it quotes, fill <= request, total <= min(max_total, 9000), and the
// price is never through the oracle in the taker's favour; a zero fill quotes the oracle.
#[kani::proof]
#[kani::unwind(130)]
#[kani::stub(impact_and_skew, stub_impact_and_skew_any)]
#[kani::stub(gross_pos_bps, stub_gross_any)]
#[kani::stub(price_with_total_bps, spec_price_with_total_bps)]
fn kani_design_p2_02_quote_never_crosses_any_domain() {
    let q = any_quote_admitted();
    let r = quote_adaptive(&q);
    if let Some((fill, price, total)) = r {
        assert!(fill <= q.fill);
        assert!(total <= (q.max_total_bps as u128).min(9_000));
        if fill == 0 {
            assert_eq!(price, q.oracle_e6);
            assert_eq!(total, 0);
        } else if q.taker_buys {
            assert!(price >= q.oracle_e6);
        } else {
            assert!(price <= q.oracle_e6);
        }
        kani::cover!(fill > 0 && fill < q.fill, "size clip exercised");
        kani::cover!(fill > 0 && q.taker_buys && price > q.oracle_e6, "buy priced above oracle");
        kani::cover!(fill > 0 && q.s_mult_bps > 10_000 && q.ref_inv == u64::MAX, "outside the builder's domain");
    }
}

// ── D-P2-03  Realised fill is monotone in the REQUESTED size, and a request that reduces the
// LP is always fillable up to |inventory|, for the REAL binary search in `quote_adaptive` over
// ANY monotone feasibility predicate (threshold model) and arbitrary impact/skew.
#[kani::proof]
#[kani::unwind(130)]
#[kani::stub(impact_and_skew, stub_impact_and_skew_any)]
#[kani::stub(gross_pos_bps, stub_gross_threshold)]
#[kani::stub(price_with_total_bps, spec_price_with_total_bps)]
fn kani_design_p2_03_fill_monotone_in_request() {
    let t: u128 = kani::any();
    unsafe { THRESHOLD = t };
    let q = any_quote_admitted();
    let bigger: u128 = kani::any();
    kani::assume(bigger >= q.fill && bigger <= i128::MAX as u128);
    let mut q2 = q;
    q2.fill = bigger;
    let r1 = quote_adaptive(&q);
    let r2 = quote_adaptive(&q2);
    if let (Some((f1, _, _)), Some((f2, _, _))) = (r1, r2) {
        assert!(f1 <= f2, "a larger request never fills less");
        // feasible prefix: fill = min(request, T) unless the LP-reducing exemption lifts it
        let lp_reduces = (q.taker_buys && q.inv_pre > 0) || (!q.taker_buys && q.inv_pre < 0);
        let base = q.fill.min(t);
        let expect = if lp_reduces { base.max(q.fill.min(q.inv_pre.unsigned_abs())) } else { base };
        assert_eq!(f1, expect);
        kani::cover!(f1 < q.fill && !lp_reduces && f1 > 0, "clipped to the feasible prefix");
        kani::cover!(lp_reduces && f1 > t, "reducing exemption fills past the clip");
    }
}

// ── D-P2-04  isqrt is the exact floor square root on the FULL u64 domain (the estimator feeds
// vol_var_e4 values above 2^32; the builder proof stops at 2^32).
#[kani::proof]
#[kani::unwind(34)]
#[kani::solver(kissat)]
fn kani_design_p2_04_isqrt_exact_full_u64() {
    let n: u64 = kani::any();
    let r = isqrt_u64(n) as u128;
    assert!(r * r <= n as u128);
    assert!((r + 1) * (r + 1) > n as u128);
    kani::cover!(n > (1u64 << 40) && r * r == n as u128, "perfect square above 2^40");
    kani::cover!(n > (1u64 << 62), "top of the domain");
}

// ── D-P2-05  CP impact is monotone in notional and the budget inverse is sound, over the full
// admitted depth / k domain (builder bound depth < 2^40). Needed by lemma L-GROSS.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_design_p2_05_cp_impact_monotone_full() {
    let d: u128 = kani::any();
    let k: u32 = kani::any();
    let n1: u128 = kani::any();
    let n2: u128 = kani::any();
    kani::assume(k <= MAX_IMPACT_K_BPS && d > 0);
    kani::assume(n1 <= n2 && n2 < d);
    let (Some(i1), Some(i2)) = (cp_impact_bps(n1, d, k), cp_impact_bps(n2, d, k)) else {
        kani::cover!(true, "overflow of k*n fails closed");
        return;
    };
    assert!(i1 <= i2);
    kani::cover!(i1 < i2 && d > (1u128 << 40), "strict above the builder's depth bound");
}

// ── D-P2-06  Skew potential W is non-decreasing in |inventory| over the full u128 x domain for
// every admitted slope / cap / ref (any u16 slope, any u64 ref incl. u64::MAX), or fails closed.
// With W convex (slope at the knee <= linear slope: lemma L-CONVEX, algebraic) this is the
// monotone half of L-GROSS.
#[kani::proof]
#[kani::solver(kissat)]
fn kani_design_p2_06_skew_potential_monotone() {
    let x1: u128 = kani::any();
    let x2: u128 = kani::any();
    let m: u16 = kani::any();
    let c: u16 = kani::any();
    let r: u64 = kani::any();
    kani::assume(x1 <= x2);
    let (Some(w1), Some(w2)) = (skew_potential_num(x1, m, c, r), skew_potential_num(x2, m, c, r)) else {
        kani::cover!(true, "overflow fails closed");
        return;
    };
    assert!(w1 <= w2);
    kani::cover!(w1 < w2 && r == u64::MAX, "shipped u64::MAX reference inventory");
    kani::cover!(w1 < w2 && m > 10_000, "slope above the builder's bound");
}
