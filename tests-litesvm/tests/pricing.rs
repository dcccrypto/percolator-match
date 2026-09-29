//! Kind-2 pricing through the compiled program: 5. adaptive fee, 6. constant-product
//! impact with size clip, 7. skew surcharge / thin-side rebate. Every expected price is
//! written out from the formula; each mechanism has a control where only that mechanism's
//! parameter is changed.
mod common;
use common::*;
use percolator_match::v2::V2Config;
use percolator_match::vamm::InitParams;
use percolator_match::{FLAG_PARTIAL_OK, FLAG_VALID};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;

fn k2(env: &mut Env, lp: &Keypair, core: &InitParams, v2: V2Config) -> Pubkey {
    let ctx = env.new_ctx(lp, &init_params(2));
    env.set_params(lp, &ctx, &set_params_from(core, true, v2))
        .expect("SetParams kind 2");
    ctx
}

// -----------------------------------------------------------------------------
// 5. Adaptive fee
// -----------------------------------------------------------------------------

const BASE5: u32 = 20;

fn core5() -> InitParams {
    InitParams {
        kind: 2,
        trading_fee_bps: 0,
        base_spread_bps: BASE5,
        max_total_bps: 500,
        ..init_params(0)
    }
}

fn vol_cfg() -> V2Config {
    V2Config {
        flags: 0,
        fee_lo_bps: 5,
        fee_hi_bps: 200,
        fee_cold_bps: 50,
        vol_a_milli: 1000,
        vol_b_den: 200,
        vol_alpha_bps: 2000,
        vol_warmup: 4,
        vol_move_cap_10bps: 100,
        vol_ref_slots: 10,
        ..V2Config::default()
    }
}

/// Feed `n` samples at `ref_slots` spacing alternating between p0 and p1, tiny
/// alternating-side fills so inventory stays ~flat. Returns the last slot/price.
fn feed(env: &mut Env, lp: &Keypair, ctx: &Pubkey, start: u64, n: u64, p0: u64, p1: u64) -> (u64, u64) {
    let mut slot = start;
    let mut px = p0;
    for i in 0..n {
        slot += 10;
        env.warp(slot);
        px = if i % 2 == 0 { p0 } else { p1 };
        let sz = if i % 2 == 0 { 1 } else { -1 };
        env.call(lp, ctx, &Call::new(100 + i, px, sz)).unwrap();
    }
    (slot, px)
}

fn probe_total_bps(env: &mut Env, lp: &Keypair, ctx: &Pubkey, px: u64) -> u128 {
    // Tiny probe at the SAME slot and price as the last feed: dt = 0, so the estimator does
    // not update; impact/skew are off, so price = ask(px, base + fee).
    let (r, _) = env.call(lp, ctx, &Call::new(9_999, px, 1)).unwrap();
    assert_eq!(r.exec_size, 1);
    // invert ask(): smallest t with ask(px, t) == exec price
    (0..=10_000u128)
        .find(|&t| ask(px, t) == r.exec_price_e6)
        .expect("exec price not of the form ask(px, t)")
}

#[test]
fn adaptive_fee_cold_before_warmup_exact() {
    let mut env = Env::v2();
    let lp = seeded_keypair(1);
    let ctx = k2(&mut env, &lp, &core5(), vol_cfg());
    env.warp(100);
    // first call ever: fee == fee_cold, exact
    let (r, _) = env.call(&lp, &ctx, &Call::new(1, 1_000_000, 1)).unwrap();
    assert_eq!(r.exec_price_e6, ask(1_000_000, (BASE5 + 50) as u128));
    assert_eq!(r.exec_price_e6, 1_007_000);
    let (r, _) = env.call(&lp, &ctx, &Call::new(2, 1_000_000, -1)).unwrap();
    assert_eq!(r.exec_price_e6, bid(1_000_000, (BASE5 + 50) as u128));
    // three volatile samples (< warmup = 4): still exactly cold even though vol is high
    let (_, px) = feed(&mut env, &lp, &ctx, 100, 3, 1_020_000, 1_000_000);
    assert_eq!(probe_total_bps(&mut env, &lp, &ctx, px), (BASE5 + 50) as u128);
}

#[test]
fn adaptive_fee_volatile_wider_than_constant_and_bounded() {
    let mut env = Env::v2();
    let lp = seeded_keypair(1);
    let vol = k2(&mut env, &lp, &core5(), vol_cfg());
    let moderate = k2(&mut env, &lp, &core5(), vol_cfg());
    let flat = k2(&mut env, &lp, &core5(), vol_cfg());
    // 11 calls: 1 seed + 10 samples at exactly vol_ref_slots spacing; sequences end at 1e6.
    let (s1, p1) = feed(&mut env, &lp, &vol, 1_000, 11, 1_000_000, 1_020_000); // +-2%
    assert_eq!(p1, 1_000_000);
    let t_vol = probe_total_bps(&mut env, &lp, &vol, p1);
    let (s2, p2) = feed(&mut env, &lp, &moderate, s1, 11, 1_000_000, 1_005_000); // +-0.5%
    let t_mod = probe_total_bps(&mut env, &lp, &moderate, p2);
    let (_, p3) = feed(&mut env, &lp, &flat, s2, 11, 1_000_000, 1_000_000); // constant
    let t_flat = probe_total_bps(&mut env, &lp, &flat, p3);
    let base = BASE5 as u128;
    println!("adaptive total bps: vol(+-2%)={t_vol} moderate(+-0.5%)={t_mod} constant={t_flat}");
    // constant price: sigma = 0 -> fee == fee_lo
    assert_eq!(t_flat, base + 5, "constant feed prices at the floor");
    assert!(t_vol > t_flat, "volatile feed must widen the spread");
    assert!(t_mod > t_flat && t_mod < t_vol, "moderate vol strictly between");
    assert!(t_vol <= base + 200 && t_mod <= base + 200, "bounded by base + fee_hi");
    assert_eq!(t_vol, base + 200, "+-2% saturates fee_hi (sigma~200bps -> 5+200+200 > 200)");
}

/// NEGATIVE CONTROL: the identical volatile feed with the vol terms zeroed
/// (vol_a_milli = 0, vol_b_den = 0) prices at the floor — the widening is the estimator.
#[test]
fn neg_adaptive_fee_vol_terms_off_no_widening() {
    let mut env = Env::v2();
    let lp = seeded_keypair(1);
    let mut c = vol_cfg();
    c.vol_a_milli = 0;
    c.vol_b_den = 0;
    let ctx = k2(&mut env, &lp, &core5(), c);
    let (_, px) = feed(&mut env, &lp, &ctx, 1_000, 11, 1_000_000, 1_020_000);
    assert_eq!(probe_total_bps(&mut env, &lp, &ctx, px), BASE5 as u128 + 5);
}

// -----------------------------------------------------------------------------
// 6. Constant-product impact
// -----------------------------------------------------------------------------

const D: u128 = 1_000_000_000_000; // $1M depth (e6)
const MAXT: u32 = 2_000;

fn core6(k: u32) -> InitParams {
    InitParams {
        kind: 2,
        trading_fee_bps: 0,
        base_spread_bps: 10,
        max_total_bps: MAXT,
        impact_k_bps: k,
        liquidity_notional_e6: D,
        ..init_params(0)
    }
}

fn cp_expected(n: u128, k: u128) -> u128 {
    if k == 0 {
        0
    } else {
        (k * n).div_ceil(D - n)
    }
}

fn sizes() -> Vec<i128> {
    // 20 sizes, geometric-ish, 1e6 .. 1.5e11 (notional == size at oracle 1e6)
    let mut v = vec![];
    let mut s: f64 = 1e6;
    for _ in 0..20 {
        v.push(s as i128);
        s *= 1.83;
    }
    v
}

#[test]
fn cp_impact_monotone_in_size_exact_formula() {
    let mut env = Env::v2();
    let lp = seeded_keypair(1);
    let ctx = k2(&mut env, &lp, &core6(10_000), fixed_fee_v2(20));
    env.warp(5);
    let mut last = 0u64;
    let ss = sizes();
    assert!(*ss.last().unwrap() < 160_000_000_000);
    for (i, &sz) in ss.iter().enumerate() {
        let (r, _) = env.call(&lp, &ctx, &Call::new(i as u64, 1_000_000, sz)).unwrap();
        assert_eq!(r.exec_size, sz, "within budget: full fill");
        let want = ask(1_000_000, 30 + cp_expected(sz as u128, 10_000));
        assert_eq!(r.exec_price_e6, want, "size {sz}");
        assert!(r.exec_price_e6 >= last, "monotone non-decreasing in size");
        last = r.exec_price_e6;
    }
    let first = ask(1_000_000, 30 + cp_expected(ss[0] as u128, 10_000));
    assert!(last > first, "impact must actually grow over the sweep");
    // sells mirror
    let (r, _) = env.call(&lp, &ctx, &Call::new(99, 1_000_000, -ss[15])).unwrap();
    assert_eq!(
        r.exec_price_e6,
        bid(1_000_000, 30 + cp_expected(ss[15] as u128, 10_000))
    );
}

#[test]
fn cp_impact_huge_size_is_size_clipped_not_price_clamped() {
    let mut env = Env::v2();
    let lp = seeded_keypair(1);
    let ctx = k2(&mut env, &lp, &core6(10_000), fixed_fee_v2(20));
    env.warp(5);
    let req: i128 = 10_000_000_000_000; // 10x depth
    let (r, _) = env.call(&lp, &ctx, &Call::new(1, 1_000_000, req)).unwrap();
    let budget = (MAXT - 30) as u128;
    let n_max = budget * D / (10_000 + budget);
    assert_eq!(r.exec_size as u128, n_max, "clipped to the budget-inverse fill");
    assert_eq!(r.flags & 0xff, FLAG_VALID | FLAG_PARTIAL_OK);
    let total = 30 + cp_expected(n_max, 10_000);
    assert!(total <= MAXT as u128);
    assert_eq!(r.exec_price_e6, ask(1_000_000, total));
    println!("CP clip: req {req} -> fill {} at {} bps", r.exec_size, total);

    // Contrast: v1 kind-1 pricing with the same depth/limits fills EVERYTHING at the clamp.
    let k1 = env.new_ctx(
        &lp,
        &InitParams {
            kind: 1,
            ..core6(10_000)
        },
    );
    let (r1, _) = env.call(&lp, &k1, &Call::new(2, 1_000_000, req)).unwrap();
    assert_eq!(r1.exec_size, req, "kind 1 fills the whole request");
    assert_eq!(r1.exec_price_e6, ask(1_000_000, MAXT as u128), "at the max_total clamp");
}

/// NEGATIVE CONTROL: impact_k_bps = 0 — every size (including the huge one) at the same
/// price, full fill.
#[test]
fn neg_cp_impact_k_zero_flat_price_full_fill() {
    let mut env = Env::v2();
    let lp = seeded_keypair(1);
    let ctx = k2(&mut env, &lp, &core6(0), fixed_fee_v2(20));
    env.warp(5);
    let flat = ask(1_000_000, 30);
    for (i, &sz) in sizes().iter().chain([10_000_000_000_000i128].iter()).enumerate() {
        let (r, _) = env.call(&lp, &ctx, &Call::new(i as u64, 1_000_000, sz)).unwrap();
        assert_eq!(r.exec_size, sz);
        assert_eq!(r.exec_price_e6, flat, "size {sz}");
        assert_eq!(r.flags & 0xff, FLAG_VALID);
    }
}

// -----------------------------------------------------------------------------
// 7. Skew surcharge / thin-side rebate
// -----------------------------------------------------------------------------

const P7: u64 = 1_000_000;
const REF: u64 = 10_000;

fn core7(s_mult: u16) -> InitParams {
    InitParams {
        kind: 2,
        trading_fee_bps: 0,
        base_spread_bps: 50,
        max_total_bps: 1_000,
        skew_spread_mult_bps: s_mult,
        ..init_params(0)
    }
}

fn cfg7(r: u16) -> V2Config {
    V2Config {
        thin_rebate_mult_bps: r,
        skew_cap_bps: 300,
        rebate_cap_bps: 150,
        skew_ref_inventory: REF,
        ..fixed_fee_v2(20)
    }
}

/// Fresh ctx, optionally pushed to LP inventory -5000 (taker bought 5000), then one probe.
fn skew_probe(s: u16, r: u16, pre_short: bool, probe: i128) -> u64 {
    let mut env = Env::v2();
    let lp = seeded_keypair(1);
    let ctx = k2(&mut env, &lp, &core7(s), cfg7(r));
    env.warp(5);
    if pre_short {
        env.call(&lp, &ctx, &Call::new(1, P7, 5_000)).unwrap();
        assert_eq!(env.ctx_struct(&ctx).inventory_base, -5_000);
    }
    let (ret, _) = env.call(&lp, &ctx, &Call::new(2, P7, probe)).unwrap();
    assert_eq!(ret.exec_size, probe);
    ret.exec_price_e6
}

#[test]
fn skew_surcharge_and_rebate_exact() {
    // fixed part = base 50 + fee 20 = 70 bps
    // flat buy 100: surcharge avg ceil(400*(0+100)/(2*10000)) = 2
    assert_eq!(skew_probe(400, 100, false, 100), ask(P7, 72));
    // short 5000, buy 100 (worsens): ceil(400*(5000+5100)/20000) = 202
    assert_eq!(skew_probe(400, 100, true, 100), ask(P7, 272));
    // flat sell 100 (worsens from 0): 2
    assert_eq!(skew_probe(400, 100, false, -100), bid(P7, 72));
    // short 5000, sell 100 (reduces): rebate floor(100*(5000+4900)/20000) = 49 -> 70-49
    assert_eq!(skew_probe(400, 100, true, -100), bid(P7, 21));
    // bigger rebate slope r = s = 400: floor(400*9900/20000)=198 -> capped 150 -> 70-150<0
    // -> clamped to 0: exactly the oracle, never through it.
    let p = skew_probe(400, 400, true, -100);
    assert_eq!(p, P7, "rebate larger than the fixed spread is floored at the oracle");
}

#[test]
fn skew_worsening_buy_pays_more_reducing_sell_pays_less_than_flat() {
    for r in [0u16, 100, 250, 400] {
        let buy_flat = skew_probe(400, r, false, 100);
        let buy_short = skew_probe(400, r, true, 100);
        let sell_flat = skew_probe(400, r, false, -100);
        let sell_short = skew_probe(400, r, true, -100);
        assert!(buy_short > buy_flat, "r={r}: worsening buy pays more");
        assert!(buy_flat >= P7 && buy_short >= P7);
        assert!(sell_flat <= P7 && sell_short <= P7);
        if r > 0 {
            assert!(sell_short > sell_flat, "r={r}: reducing sell gets a better (higher) bid");
        } else {
            // no rebate: reducing sell pays the fixed spread, flat sell pays fixed + 2
            assert_eq!(sell_short, bid(P7, 70));
        }
    }
}

/// NEGATIVE CONTROL: skew_spread_mult_bps = 0 (and rebate 0) — inventory makes no
/// difference to either side.
#[test]
fn neg_skew_mult_zero_inventory_irrelevant() {
    assert_eq!(skew_probe(0, 0, false, 100), skew_probe(0, 0, true, 100));
    assert_eq!(skew_probe(0, 0, false, -100), skew_probe(0, 0, true, -100));
    assert_eq!(skew_probe(0, 0, true, 100), ask(P7, 70));
    assert_eq!(skew_probe(0, 0, true, -100), bid(P7, 70));
}

#[test]
fn skew_round_trip_from_flat_never_beats_zero_skew() {
    fn round_trip_cost(s: u16, r: u16, x: i128) -> i128 {
        let mut env = Env::v2();
        let lp = seeded_keypair(1);
        let ctx = k2(&mut env, &lp, &core7(s), cfg7(r));
        env.warp(5);
        let (b, _) = env.call(&lp, &ctx, &Call::new(1, P7, x)).unwrap();
        let (sl, _) = env.call(&lp, &ctx, &Call::new(2, P7, -x)).unwrap();
        assert_eq!(b.exec_size, x);
        assert_eq!(sl.exec_size, -x);
        assert_eq!(env.ctx_struct(&ctx).inventory_base, 0);
        // taker pays buy notional, receives sell notional
        x * (b.exec_price_e6 as i128 - sl.exec_price_e6 as i128)
    }
    for x in [1i128, 7, 100, 5_000, 20_000, 1_000_000] {
        let zero = round_trip_cost(0, 0, x);
        for (s, r) in [(400u16, 100u16), (400, 400), (10_000, 10_000), (1, 1)] {
            let c = round_trip_cost(s, r, x);
            assert!(c >= zero, "x={x} s={s} r={r}: skewed round trip {c} < zero-skew {zero}");
        }
    }
}
