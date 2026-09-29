//! P2 matcher v2 — property tests (proptest) on the pricing arithmetic. These complement
//! the Kani harnesses in src/v2.rs: Kani proves the properties on bounded domains, these
//! sample realistic magnitudes (u64 prices, 1e18-scale sizes) the solver cannot reach.

use percolator_match::v2::{
    adaptive_fee_bps, cp_impact_bps, cp_max_notional_for_budget, quote_adaptive, requested_fee_bps,
    skew_net_bps, AdaptiveQuoteIn, CallExt, V2Config, V2State,
};
use proptest::prelude::*;

fn cfg(lo: u16, hi: u16, a: u16, b: u16) -> V2Config {
    V2Config {
        fee_lo_bps: lo,
        fee_hi_bps: hi,
        fee_cold_bps: lo,
        vol_a_milli: a,
        vol_b_den: b,
        ..V2Config::default()
    }
}

prop_compose! {
    fn skew_params()(s in 0u16..=10_000, rf in 0u16..=10_000, sc in 0u16..=5_000,
                     rcf in 0u16..=10_000, ref_sel in 0u8..4, ref_small in 1u64..=1_000_000_000_000, ref_any in 1u64..=u64::MAX)
        -> (u16, u16, u16, u16, u64) {
        let r = (s as u32 * rf as u32 / 10_000) as u16;          // r <= s
        let rc = (sc as u32 * rcf as u32 / 10_000) as u16;       // rc <= sc
        // full u64 domain incl. the u64::MAX default used when max_inventory_abs == 0
        // (security review: the shipped default sits outside the Kani-proven domain)
        let ref_inv = match ref_sel { 0 => u64::MAX, 1 => ref_any, _ => ref_small };
        (s, r, sc, rc, ref_inv)
    }
}

#[allow(clippy::too_many_arguments)]
fn quote_in(
    oracle: u64,
    fill: u128,
    buy: bool,
    inv: i128,
    fee: u128,
    k: u32,
    depth: u128,
    sp: (u16, u16, u16, u16, u64),
) -> AdaptiveQuoteIn {
    AdaptiveQuoteIn {
        oracle_e6: oracle,
        fill,
        taker_buys: buy,
        inv_pre: inv,
        base_spread_bps: 20,
        max_total_bps: 600,
        fee_bps: fee,
        impact_k_bps: k,
        depth_e6: depth,
        s_mult_bps: sp.0,
        r_mult_bps: sp.1,
        skew_cap_bps: sp.2,
        rebate_cap_bps: sp.3,
        ref_inv: sp.4,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]

    #[test]
    fn fee_bounded_and_monotone_in_vol(lo in 0u16..=500, span in 0u16..=500, a in 0u16..=5000,
                                       b in 0u16..=1000, v1 in any::<u64>(), v2 in any::<u64>()) {
        let hi = lo + span;
        let c = cfg(lo, hi, a, b);
        let (vl, vh) = if v1 <= v2 { (v1, v2) } else { (v2, v1) };
        let s1 = V2State { vol_var_e4: vl, ..V2State::default() };
        let s2 = V2State { vol_var_e4: vh, ..V2State::default() };
        let f1 = adaptive_fee_bps(&c, &s1);
        let f2 = adaptive_fee_bps(&c, &s2);
        prop_assert!(f1 >= lo as u128 && f1 <= hi as u128);
        prop_assert!(f1 <= f2);
    }

    #[test]
    fn cp_impact_monotone_and_inverse_sound(depth in 1u128..=1u128 << 90, k in 0u32..=100_000,
                                            n1 in any::<u128>(), n2 in any::<u128>(), b in 0u128..=9_000) {
        let (a, c) = if n1 % depth <= n2 % depth { (n1 % depth, n2 % depth) } else { (n2 % depth, n1 % depth) };
        let i1 = cp_impact_bps(a, depth, k);
        let i2 = cp_impact_bps(c, depth, k);
        if let (Some(i1), Some(i2)) = (i1, i2) { prop_assert!(i1 <= i2); }
        let n = cp_max_notional_for_budget(depth, k, b);
        if k > 0 && n < depth {
            if let Some(i) = cp_impact_bps(n, depth, k) { prop_assert!(i <= b); }
        }
    }

    #[test]
    fn skew_monotone_in_size(inv in -(1i128 << 60)..(1i128 << 60), f1 in 1u128..(1u128 << 58),
                             f2 in 1u128..(1u128 << 58), sells in any::<bool>(), sp in skew_params()) {
        let (a, b) = if f1 <= f2 { (f1, f2) } else { (f2, f1) };
        let x = skew_net_bps(inv, a, sells, sp.0, sp.1, sp.2, sp.3, sp.4);
        let y = skew_net_bps(inv, b, sells, sp.0, sp.1, sp.2, sp.3, sp.4);
        if let (Some(x), Some(y)) = (x, y) { prop_assert!(x <= y, "{x} > {y}"); }
    }

    #[test]
    fn skew_split_never_cheaper_and_round_trip(inv in -(1i128 << 50)..(1i128 << 50),
                                               f1 in 1u128..(1u128 << 48), f2 in 1u128..(1u128 << 48),
                                               sells in any::<bool>(), sp in skew_params()) {
        let whole = skew_net_bps(inv, f1 + f2, sells, sp.0, sp.1, sp.2, sp.3, sp.4);
        let p1 = skew_net_bps(inv, f1, sells, sp.0, sp.1, sp.2, sp.3, sp.4);
        let mid = if sells { inv - f1 as i128 } else { inv + f1 as i128 };
        let p2 = skew_net_bps(mid, f2, sells, sp.0, sp.1, sp.2, sp.3, sp.4);
        if let (Some(w), Some(p1), Some(p2)) = (whole, p1, p2) {
            let split = p1 * f1 as i128 + p2 * f2 as i128;
            prop_assert!(split + (f1 + f2) as i128 >= w * (f1 + f2) as i128);
        }
        // round trip from flat never pays the taker
        let out = skew_net_bps(0, f1, sells, sp.0, sp.1, sp.2, sp.3, sp.4);
        let back_start = if sells { -(f1 as i128) } else { f1 as i128 };
        let back = skew_net_bps(back_start, f1, !sells, sp.0, sp.1, sp.2, sp.3, sp.4);
        if let (Some(o), Some(b)) = (out, back) { prop_assert!(o + b >= 0); }
    }

    #[test]
    fn skew_monotone_in_skew(inv in -(1i128 << 55)..(1i128 << 55), d in 0i128..(1i128 << 55),
                             f in 1u128..(1u128 << 55), sp in skew_params()) {
        // LP sells (taker buys): starting more short is never cheaper.
        let x = skew_net_bps(inv, f, true, sp.0, sp.1, sp.2, sp.3, sp.4);
        let y = skew_net_bps(inv - d, f, true, sp.0, sp.1, sp.2, sp.3, sp.4);
        if let (Some(x), Some(y)) = (x, y) { prop_assert!(x <= y); }
        // LP buys (taker sells): starting more long is never cheaper.
        let x = skew_net_bps(inv, f, false, sp.0, sp.1, sp.2, sp.3, sp.4);
        let y = skew_net_bps(inv + d, f, false, sp.0, sp.1, sp.2, sp.3, sp.4);
        if let (Some(x), Some(y)) = (x, y) { prop_assert!(x <= y); }
    }

    #[test]
    fn quote_never_crosses_oracle_and_monotone(oracle in 1u64..=1_000_000_000_000_000,
                                               f1 in 1u128..(1u128 << 50), f2 in 1u128..(1u128 << 50),
                                               buy in any::<bool>(), inv in -(1i128 << 50)..(1i128 << 50),
                                               fee in 0u128..=500, k in 0u32..=100_000,
                                               depth in 1u128..(1u128 << 80), sp in skew_params()) {
        for f in [f1, f2] {
            if let Some((fill, price, total)) = quote_adaptive(&quote_in(oracle, f, buy, inv, fee, k, depth, sp)) {
                prop_assert!(fill <= f && total <= 600);
                if fill > 0 {
                    if buy { prop_assert!(price >= oracle); } else { prop_assert!(price <= oracle); }
                } else {
                    prop_assert_eq!(price, oracle);
                }
            }
        }
        // price monotone in REALIZED fill: re-quote at the realized fills (no further clip)
        let (a, b) = if f1 <= f2 { (f1, f2) } else { (f2, f1) };
        let qa = quote_adaptive(&quote_in(oracle, a, buy, inv, fee, k, depth, sp));
        let qb = quote_adaptive(&quote_in(oracle, b, buy, inv, fee, k, depth, sp));
        if let (Some((fa, pa, _)), Some((fb, pb, _))) = (qa, qb) {
            if fa == a && fb == b && fa > 0 {
                if buy { prop_assert!(pa <= pb); } else { prop_assert!(pa >= pb); }
            }
        }
    }

    #[test]
    fn ext_roundtrip(h in proptest::option::of(any::<u64>()), m in proptest::option::of(any::<u64>()),
                     fr in any::<bool>(), tr in any::<bool>(), band in proptest::option::of(any::<u16>())) {
        let e = CallExt { headroom_q: h, mark_slot: m, accepts_fee_request: fr, taker_reducing: tr, exec_band_bps: band };
        prop_assert_eq!(CallExt::parse(&e.encode()).unwrap(), e);
    }

    #[test]
    fn requested_fee_bounded(o in 1u64..=1_000_000_000_000_000, p in any::<u64>()) {
        let f = requested_fee_bps(o, p);
        prop_assert!(f <= 1023);
    }

    /// Dedicated monotonicity-in-size property on a domain where the size clip rarely
    /// binds, so the assertion is exercised on most cases (the general property above
    /// only reaches it ~2% of the time). Counted: at least half the cases must compare.
    #[test]
    fn quote_monotone_in_size_dense(oracle in 1_000u64..=1_000_000_000, f1 in 1u128..(1u128 << 30),
                                    f2 in 1u128..(1u128 << 30), buy in any::<bool>(),
                                    inv in -(1i128 << 30)..(1i128 << 30), fee in 0u128..=300,
                                    k in 0u32..=20_000, sp in skew_params()) {
        let depth = 1u128 << 90;
        let (a, b) = if f1 <= f2 { (f1, f2) } else { (f2, f1) };
        let sp = (sp.0, sp.1, sp.2, sp.3, sp.4.max(1 << 20));
        let qa = quote_adaptive(&quote_in(oracle, a, buy, inv, fee, k, depth, sp)).unwrap();
        let qb = quote_adaptive(&quote_in(oracle, b, buy, inv, fee, k, depth, sp)).unwrap();
        if qa.0 == a && qb.0 == b {
            if buy { prop_assert!(qa.1 <= qb.1); } else { prop_assert!(qa.1 >= qb.1); }
            DENSE_HITS.with(|h| h.set(h.get() + 1));
        }
        DENSE_RUNS.with(|h| h.set(h.get() + 1));
        let (hits, runs) = (DENSE_HITS.with(|h| h.get()), DENSE_RUNS.with(|h| h.get()));
        if runs >= 1000 { prop_assert!(hits * 2 >= runs, "only {hits}/{runs} cases compared"); }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4000))]
    /// Realised fill never shrinks when the request grows (backtest finding).
    #[test]
    fn quote_fill_monotone_in_request(oracle in 1u64..=1_000_000_000_000, f1 in 1u128..(1u128 << 50),
                                      f2 in 1u128..(1u128 << 50), buy in any::<bool>(),
                                      inv in -(1i128 << 50)..(1i128 << 50), fee in 0u128..=300,
                                      k in 0u32..=100_000, depth in 1u128..(1u128 << 70), sp in skew_params()) {
        let (a, b) = if f1 <= f2 { (f1, f2) } else { (f2, f1) };
        let qa = quote_adaptive(&quote_in(oracle, a, buy, inv, fee, k, depth, sp));
        let qb = quote_adaptive(&quote_in(oracle, b, buy, inv, fee, k, depth, sp));
        if let (Some(x), Some(y)) = (qa, qb) { prop_assert!(x.0 <= y.0, "{} > {}", x.0, y.0); }
    }
}

thread_local! {
    static DENSE_HITS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static DENSE_RUNS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}
