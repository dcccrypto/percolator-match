//! Items 2 (LP headroom), 3 (authoritative stale mark), 4 (observed-staleness fallback),
//! 9 (kind-2 asset binding) — each with a negative control (same setup, one variable
//! changed, opposite outcome).
mod common;
use common::*;
use percolator_match::v2::{CallExt, V2Config, V2_FLAG_STALE_ALLOW_REDUCING};
use percolator_match::vamm::InitParams;
use percolator_match::{FLAG_PARTIAL_OK, FLAG_VALID};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;

const P: u64 = 2_000_000;

fn ext_h(h: u64) -> CallExt {
    CallExt {
        headroom_q: Some(h),
        mark_slot: None,
        accepts_fee_request: false,
        ..CallExt::default()
    }
}
fn ext_m(m: u64) -> CallExt {
    CallExt {
        headroom_q: None,
        mark_slot: Some(m),
        accepts_fee_request: false,
        ..CallExt::default()
    }
}

/// kind-2 InitParams-equivalent core (no impact, no skew) for SetParams.
fn k2_core() -> InitParams {
    InitParams {
        kind: 2,
        ..init_params(0)
    }
}

/// Fresh ctx of `kind` (0/1/2). For kind 2, reconfigured to a fixed 20 bps fee with every
/// guard off so the mechanism under test is the only thing switched on.
fn mk(env: &mut Env, lp: &Keypair, kind: u8) -> Pubkey {
    if kind == 2 {
        let ctx = env.new_ctx(lp, &init_params(2));
        env.set_params(lp, &ctx, &set_params_from(&k2_core(), true, fixed_fee_v2(20)))
            .unwrap();
        ctx
    } else {
        env.new_ctx(lp, &init_params(kind))
    }
}

/// Attach a v2 block (guards only) to a kind-0/1 ctx, or a guarded fixed-fee block to kind 2.
fn guard(env: &mut Env, lp: &Keypair, ctx: &Pubkey, kind: u8, g: V2Config) {
    let r = if kind == 2 {
        let mut c = fixed_fee_v2(20);
        c.flags = g.flags;
        c.max_mark_age_slots = g.max_mark_age_slots;
        c.observed_stale_slots = g.observed_stale_slots;
        env.set_params(lp, ctx, &set_params_from(&k2_core(), true, c))
    } else {
        env.set_params(lp, ctx, &set_params_from(&init_params(kind), true, g))
    };
    r.expect("configure guard");
}

// -----------------------------------------------------------------------------
// 2. Headroom
// -----------------------------------------------------------------------------

#[test]
fn headroom_clips_fill_and_sets_partial_ok() {
    for kind in [0u8, 1, 2] {
        let mut env = Env::v2();
        let lp = seeded_keypair(1);
        let ctx = mk(&mut env, &lp, kind);
        env.warp(50);
        // H < req, both sides
        let (r, _) = env
            .call(&lp, &ctx, &Call::new(1, P, 1_000).ext(ext_h(300)))
            .unwrap();
        assert_eq!(r.exec_size, 300, "kind {kind} buy clipped to H");
        assert_eq!(r.flags & 0xff, FLAG_VALID | FLAG_PARTIAL_OK);
        assert!(r.exec_price_e6 > P);
        let (r, _) = env
            .call(&lp, &ctx, &Call::new(2, P, -1_000).ext(ext_h(300)))
            .unwrap();
        assert_eq!(r.exec_size, -300, "kind {kind} sell clipped to H");
        assert_eq!(r.flags & 0xff, FLAG_VALID | FLAG_PARTIAL_OK);
        // H = 0 -> zero fill at oracle
        let before = env.ctx_data(&ctx);
        let (r, _) = env
            .call(&lp, &ctx, &Call::new(3, P, 1_000).ext(ext_h(0)))
            .unwrap();
        assert_eq!(r.exec_size, 0, "kind {kind} H=0 zero fill");
        assert_eq!(r.exec_price_e6, P, "kind {kind} zero fill priced at oracle");
        assert_eq!(r.flags & 0xff, FLAG_VALID | FLAG_PARTIAL_OK);
        assert_eq!(
            env.ctx_struct(&ctx).inventory_base,
            percolator_match::vamm::MatcherCtx::read_from(&before[64..])
                .unwrap()
                .inventory_base,
            "zero fill must not move inventory"
        );
        // H >= req -> full fill, no PARTIAL_OK
        let (r, _) = env
            .call(&lp, &ctx, &Call::new(4, P, 1_000).ext(ext_h(1_000)))
            .unwrap();
        assert_eq!(r.exec_size, 1_000);
        assert_eq!(r.flags & 0xff, FLAG_VALID);
    }
}

/// NEGATIVE CONTROL: the identical call with the legacy (all-zero) extension fills in full.
#[test]
fn neg_headroom_legacy_ext_fills_full() {
    for kind in [0u8, 1, 2] {
        let mut env = Env::v2();
        let lp = seeded_keypair(1);
        let ctx = mk(&mut env, &lp, kind);
        env.warp(50);
        let (r, _) = env.call(&lp, &ctx, &Call::new(1, P, 1_000)).unwrap();
        assert_eq!(r.exec_size, 1_000, "kind {kind}");
        assert_eq!(r.flags & 0xff, FLAG_VALID);
        let (r, _) = env.call(&lp, &ctx, &Call::new(2, P, -1_000)).unwrap();
        assert_eq!(r.exec_size, -1_000);
    }
}

#[test]
fn headroom_batch_same_asset_same_direction_shares_budget() {
    for kind in [0u8, 1, 2] {
        let mut env = Env::v2();
        let lp = seeded_keypair(1);
        let ctx = mk(&mut env, &lp, kind);
        env.warp(50);
        let b = Batch::with_ext(
            1,
            vec![
                Leg::new(0, P, 200).ext(ext_h(300)),
                Leg::new(0, P, 200).ext(ext_h(300)),
                Leg::new(0, P, 200).ext(ext_h(300)),
            ],
        );
        let (rets, _) = env.batch(&lp, &ctx, &b).unwrap();
        let sizes: Vec<i128> = rets.iter().map(|r| r.exec_size).collect();
        assert_eq!(sizes, vec![200, 100, 0], "kind {kind}");
        assert!(sizes.iter().sum::<i128>() <= 300);
        assert_eq!(rets[1].flags & 0xff, FLAG_VALID | FLAG_PARTIAL_OK);
        assert_eq!(rets[2].flags & 0xff, FLAG_VALID | FLAG_PARTIAL_OK);
        assert_eq!(env.ctx_struct(&ctx).inventory_base, -300);
    }
}

/// NEGATIVE CONTROL: opposite directions on the same asset do NOT share the headroom.
#[test]
fn neg_headroom_batch_opposite_directions_do_not_share() {
    for kind in [0u8, 1, 2] {
        let mut env = Env::v2();
        let lp = seeded_keypair(1);
        let ctx = mk(&mut env, &lp, kind);
        env.warp(50);
        let b = Batch::with_ext(
            1,
            vec![
                Leg::new(0, P, 200).ext(ext_h(300)),
                Leg::new(0, P, -200).ext(ext_h(300)),
                Leg::new(0, P, 200).ext(ext_h(300)),
            ],
        );
        let (rets, _) = env.batch(&lp, &ctx, &b).unwrap();
        let sizes: Vec<i128> = rets.iter().map(|r| r.exec_size).collect();
        // leg 3 shares with leg 1 (same dir): 300 - 200 = 100
        assert_eq!(sizes, vec![200, -200, 100], "kind {kind}");
    }
    // and different assets on a kind-0 ctx (no binding) do not share either
    let mut env = Env::v2();
    let lp = seeded_keypair(1);
    let ctx = mk(&mut env, &lp, 0);
    let b = Batch::with_ext(
        1,
        vec![
            Leg::new(0, P, 200).ext(ext_h(300)),
            Leg::new(1, P, 200).ext(ext_h(300)),
        ],
    );
    let (rets, _) = env.batch(&lp, &ctx, &b).unwrap();
    assert_eq!(rets[0].exec_size, 200);
    assert_eq!(rets[1].exec_size, 200);
}

// -----------------------------------------------------------------------------
// 3. Authoritative stale mark
// -----------------------------------------------------------------------------

fn age_guard(age: u16, flags: u8) -> V2Config {
    V2Config {
        flags,
        max_mark_age_slots: age,
        ..V2Config::default()
    }
}

#[test]
fn stale_mark_refused_8002_ctx_unchanged_and_age_eq_max_fills() {
    for kind in [1u8, 2] {
        let mut env = Env::v2();
        let lp = seeded_keypair(1);
        let ctx = mk(&mut env, &lp, kind);
        guard(&mut env, &lp, &ctx, kind, age_guard(10, 0));
        env.warp(1_000);
        let before = env.ctx_data(&ctx);
        let e = expect_err(env.call(&lp, &ctx, &Call::new(1, P, 100).ext(ext_m(989))));
        assert_eq!(e, custom(8002), "kind {kind}: age 11 > 10");
        assert_eq!(env.ctx_data(&ctx), before, "kind {kind}: refused call left ctx bytes");
        // CONTROL (one variable: mark_slot 989 -> 990, age == max): fills
        let (r, _) = env
            .call(&lp, &ctx, &Call::new(2, P, 100).ext(ext_m(990)))
            .unwrap();
        assert_eq!(r.exec_size, 100, "kind {kind}: age == max fills");
        // future mark
        let before = env.ctx_data(&ctx);
        let e = expect_err(env.call(&lp, &ctx, &Call::new(3, P, 100).ext(ext_m(1_001))));
        assert_eq!(e, custom(8003), "kind {kind}: mark_slot in the future");
        assert_eq!(env.ctx_data(&ctx), before);
        // mark == now fills
        let (r, _) = env
            .call(&lp, &ctx, &Call::new(4, P, 100).ext(ext_m(1_000)))
            .unwrap();
        assert_eq!(r.exec_size, 100);
    }
}

/// NEGATIVE CONTROL: the same stale mark_slot on a ctx whose guard is disabled
/// (max_mark_age_slots = 0) fills — the refusal comes from the configured guard.
#[test]
fn neg_stale_mark_guard_disabled_fills() {
    for kind in [1u8, 2] {
        let mut env = Env::v2();
        let lp = seeded_keypair(1);
        let ctx = mk(&mut env, &lp, kind);
        guard(&mut env, &lp, &ctx, kind, age_guard(0, 0));
        env.warp(1_000);
        let (r, _) = env
            .call(&lp, &ctx, &Call::new(1, P, 100).ext(ext_m(1)))
            .unwrap();
        assert_eq!(r.exec_size, 100, "kind {kind}");
    }
}

#[test]
fn stale_allow_reducing_clips_to_inventory_increasing_still_refused() {
    for kind in [1u8, 2] {
        let mut env = Env::v2();
        let lp = seeded_keypair(1);
        let ctx = mk(&mut env, &lp, kind);
        guard(&mut env, &lp, &ctx, kind, age_guard(10, V2_FLAG_STALE_ALLOW_REDUCING));
        env.warp(1_000);
        // fresh: taker buys 500 -> LP inventory -500
        env.call(&lp, &ctx, &Call::new(1, P, 500).ext(ext_m(1_000)))
            .unwrap();
        assert_eq!(env.ctx_struct(&ctx).inventory_base, -500);
        env.warp(1_100); // mark 1000 is now 100 slots old (> 10)
        // increasing (taker buys again) under a stale mark -> refused
        let before = env.ctx_data(&ctx);
        let e = expect_err(env.call(&lp, &ctx, &Call::new(2, P, 100).ext(ext_m(1_000))));
        assert_eq!(e, custom(8002), "kind {kind}: increasing trade under stale mark");
        assert_eq!(env.ctx_data(&ctx), before);
        // reducing (taker sells 800) -> fills, clipped to |inventory| = 500
        let (r, _) = env
            .call(&lp, &ctx, &Call::new(3, P, -800).ext(ext_m(1_000)))
            .unwrap();
        assert_eq!(r.exec_size, -500, "kind {kind}: clipped to |inventory|");
        assert_eq!(r.flags & 0xff, FLAG_VALID | FLAG_PARTIAL_OK);
        assert_eq!(env.ctx_struct(&ctx).inventory_base, 0, "cannot flip");
        // flat now: any trade under the stale mark is "increasing" -> refused
        let e = expect_err(env.call(&lp, &ctx, &Call::new(4, P, -1).ext(ext_m(1_000))));
        assert_eq!(e, custom(8002));
    }
}

/// NEGATIVE CONTROL: same setup without V2_FLAG_STALE_ALLOW_REDUCING — the reducing trade
/// is refused too.
#[test]
fn neg_stale_reducing_refused_without_flag() {
    for kind in [1u8, 2] {
        let mut env = Env::v2();
        let lp = seeded_keypair(1);
        let ctx = mk(&mut env, &lp, kind);
        guard(&mut env, &lp, &ctx, kind, age_guard(10, 0));
        env.warp(1_000);
        env.call(&lp, &ctx, &Call::new(1, P, 500).ext(ext_m(1_000)))
            .unwrap();
        env.warp(1_100);
        let e = expect_err(env.call(&lp, &ctx, &Call::new(3, P, -800).ext(ext_m(1_000))));
        assert_eq!(e, custom(8002), "kind {kind}");
    }
}

// -----------------------------------------------------------------------------
// 4. Observed-staleness fallback (no mark_slot in the extension)
// -----------------------------------------------------------------------------

fn obs_guard(n: u16) -> V2Config {
    V2Config {
        observed_stale_slots: n,
        ..V2Config::default()
    }
}

#[test]
fn observed_stale_unchanged_price_refused_8002() {
    for kind in [1u8, 2] {
        let mut env = Env::v2();
        let lp = seeded_keypair(1);
        let ctx = mk(&mut env, &lp, kind);
        guard(&mut env, &lp, &ctx, kind, obs_guard(20));
        env.warp(100);
        env.call(&lp, &ctx, &Call::new(1, P, 10)).unwrap(); // anchors (P, 100)
        env.warp(120);
        // same price, age == limit: still fresh, and does NOT re-anchor
        env.call(&lp, &ctx, &Call::new(2, P, 10)).unwrap();
        env.warp(121);
        let before = env.ctx_data(&ctx);
        let e = expect_err(env.call(&lp, &ctx, &Call::new(3, P, 10)));
        assert_eq!(e, custom(8002), "kind {kind}: unchanged for 21 > 20 slots");
        assert_eq!(env.ctx_data(&ctx), before);
        // CONTROL 1 (price +1, everything else identical): fills and re-anchors
        let (r, _) = env.call(&lp, &ctx, &Call::new(4, P + 1, 10)).unwrap();
        assert_eq!(r.exec_size, 10, "kind {kind}: changed price is fresh");
        env.warp(141);
        env.call(&lp, &ctx, &Call::new(5, P + 1, 10)).unwrap();
        env.warp(142);
        let e = expect_err(env.call(&lp, &ctx, &Call::new(6, P + 1, 10)));
        assert_eq!(e, custom(8002), "re-anchored at 121");
    }
}

/// NEGATIVE CONTROL 2: observed_stale_slots = 0 — the same unchanged-price sequence fills.
#[test]
fn neg_observed_stale_disabled_fills() {
    for kind in [1u8, 2] {
        let mut env = Env::v2();
        let lp = seeded_keypair(1);
        let ctx = mk(&mut env, &lp, kind);
        guard(&mut env, &lp, &ctx, kind, obs_guard(0));
        env.warp(100);
        env.call(&lp, &ctx, &Call::new(1, P, 10)).unwrap();
        for (i, s) in [121u64, 5_000, 1_000_000].into_iter().enumerate() {
            env.warp(s);
            let (r, _) = env.call(&lp, &ctx, &Call::new(2 + i as u64, P, 10)).unwrap();
            assert_eq!(r.exec_size, 10, "kind {kind} slot {s}");
        }
    }
}

// -----------------------------------------------------------------------------
// 9. Asset binding (kind 2)
// -----------------------------------------------------------------------------

#[test]
fn kind2_asset_binding() {
    let mut env = Env::v2();
    let lp = seeded_keypair(1);
    // default kind-2 init (wrapper-tag-83 shape): unbound
    let ctx = env.new_ctx(&lp, &init_params(2));
    let bound = |d: &[u8]| u16::from_le_bytes(ctx_v2_raw(d)[28..30].try_into().unwrap());
    assert_eq!(bound(&env.ctx_data(&ctx)), 0, "fresh ctx unbound");
    env.warp(10);
    env.call(&lp, &ctx, &Call::new(1, P, 10).asset(0)).unwrap();
    assert_eq!(bound(&env.ctx_data(&ctx)), 1, "bound to asset 0 (+1)");
    let before = env.ctx_data(&ctx);
    let e = expect_err(env.call(&lp, &ctx, &Call::new(2, P, 10).asset(1)));
    assert_eq!(e, custom(8004));
    assert_eq!(env.ctx_data(&ctx), before);
    // CONTROL: another asset-0 call fills
    let (r, _) = env.call(&lp, &ctx, &Call::new(3, P, 10).asset(0)).unwrap();
    assert_eq!(r.exec_size, 10);
    // batch with a second asset is refused atomically
    let b = Batch::legacy(4, vec![Leg::new(0, P, 5), Leg::new(1, P, 5)]);
    let before = env.ctx_data(&ctx);
    assert_eq!(expect_err(env.batch(&lp, &ctx, &b)), custom(8004));
    assert_eq!(env.ctx_data(&ctx), before);

    // binding to a non-zero asset first works symmetrically
    let ctx2 = env.new_ctx(&lp, &init_params(2));
    env.call(&lp, &ctx2, &Call::new(1, P, 10).asset(7)).unwrap();
    assert_eq!(bound(&env.ctx_data(&ctx2)), 8);
    assert_eq!(
        expect_err(env.call(&lp, &ctx2, &Call::new(2, P, 10).asset(0))),
        custom(8004)
    );
}

/// NEGATIVE CONTROL: a kind-0 ctx without a v2 block has no binding — asset 1 after
/// asset 0 fills.
#[test]
fn neg_kind0_no_binding() {
    let mut env = Env::v2();
    let lp = seeded_keypair(1);
    let ctx = env.new_ctx(&lp, &init_params(0));
    env.call(&lp, &ctx, &Call::new(1, P, 10).asset(0)).unwrap();
    let (r, _) = env.call(&lp, &ctx, &Call::new(2, P, 10).asset(1)).unwrap();
    assert_eq!(r.exec_size, 10);
}

// -----------------------------------------------------------------------------
// TAKER_REDUCING (ext bit 3) under a stale mark
// -----------------------------------------------------------------------------

fn ext_stale(m: u64, taker_reducing: bool) -> CallExt {
    CallExt {
        mark_slot: Some(m),
        taker_reducing,
        ..CallExt::default()
    }
}

#[test]
fn taker_reducing_fills_unclipped_under_stale_mark_with_allow_flag() {
    for kind in [1u8, 2] {
        let mut env = Env::v2();
        let lp = seeded_keypair(1);
        let ctx = mk(&mut env, &lp, kind);
        guard(&mut env, &lp, &ctx, kind, age_guard(10, V2_FLAG_STALE_ALLOW_REDUCING));
        env.warp(1_100); // mark 1000 is 100 slots old
        assert_eq!(env.ctx_struct(&ctx).inventory_base, 0, "LP flat: no LP-reducing room");
        let (r, _) = env
            .call(&lp, &ctx, &Call::new(1, P, -300).ext(ext_stale(1_000, true)))
            .unwrap();
        assert_eq!(r.exec_size, -300, "kind {kind}: attested taker exit fills in full");
        assert_eq!(r.flags & 0xff, FLAG_VALID);
    }
}

/// NEGATIVE CONTROLS: (1) same call without the TAKER_REDUCING bit -> 8002;
/// (2) TAKER_REDUCING on a ctx without V2_FLAG_STALE_ALLOW_REDUCING -> 8002.
#[test]
fn neg_taker_reducing_requires_bit_and_allow_flag() {
    for kind in [1u8, 2] {
        let mut env = Env::v2();
        let lp = seeded_keypair(1);
        let ctx = mk(&mut env, &lp, kind);
        guard(&mut env, &lp, &ctx, kind, age_guard(10, V2_FLAG_STALE_ALLOW_REDUCING));
        env.warp(1_100);
        let before = env.ctx_data(&ctx);
        let e = expect_err(env.call(&lp, &ctx, &Call::new(1, P, -300).ext(ext_stale(1_000, false))));
        assert_eq!(e, custom(8002), "kind {kind}: no attestation");
        assert_eq!(env.ctx_data(&ctx), before);

        let mut env = Env::v2();
        let ctx = mk(&mut env, &lp, kind);
        guard(&mut env, &lp, &ctx, kind, age_guard(10, 0));
        env.warp(1_100);
        let e = expect_err(env.call(&lp, &ctx, &Call::new(1, P, -300).ext(ext_stale(1_000, true))));
        assert_eq!(e, custom(8002), "kind {kind}: ctx does not allow reducing");
    }
}

// -----------------------------------------------------------------------------
// EXEC_BAND (ext bit 4, bytes 2..4)
// -----------------------------------------------------------------------------

fn ext_band(b: Option<u16>) -> CallExt {
    CallExt {
        exec_band_bps: b,
        ..CallExt::default()
    }
}

fn total_bps(oracle: u64, exec: u64, buy: bool) -> u128 {
    (0..=10_000u128)
        .find(|&t| if buy { ask(oracle, t) == exec } else { bid(oracle, t) == exec })
        .expect("price not of the ask/bid form")
}

#[test]
fn exec_band_kind0_1_clamps_spread() {
    for kind in [0u8, 1] {
        let mut env = Env::v2();
        let lp = seeded_keypair(1);
        let ctx = mk(&mut env, &lp, kind);
        let sz = if kind == 1 { 50_000_000_000 } else { 1_000 }; // kind 1: impact pushes > band
        let (r0, _) = env.call(&lp, &ctx, &Call::new(1, P, sz)).unwrap();
        let t0 = total_bps(P, r0.exec_price_e6, true);
        let band = 25u16;
        assert!(t0 > band as u128, "kind {kind}: control quote {t0} exceeds band");
        let (r, _) = env
            .call(&lp, &ctx, &Call::new(2, P, sz).ext(ext_band(Some(band))))
            .unwrap();
        assert_eq!(r.exec_size, sz, "kind {kind}: 0/1 clamp price, not size");
        assert_eq!(total_bps(P, r.exec_price_e6, true), band as u128);
        let (r, _) = env
            .call(&lp, &ctx, &Call::new(3, P, -sz).ext(ext_band(Some(band))))
            .unwrap();
        assert_eq!(total_bps(P, r.exec_price_e6, false), band as u128);
    }
}

#[test]
fn exec_band_kind2_size_clips_within_band() {
    let core = InitParams {
        kind: 2,
        trading_fee_bps: 0,
        base_spread_bps: 10,
        max_total_bps: 2_000,
        impact_k_bps: 10_000,
        liquidity_notional_e6: 1_000_000_000_000,
        ..init_params(0)
    };
    let mut env = Env::v2();
    let lp = seeded_keypair(1);
    let ctx = env.new_ctx(&lp, &init_params(2));
    env.set_params(&lp, &ctx, &set_params_from(&core, true, fixed_fee_v2(20)))
        .unwrap();
    env.warp(5);
    const O: u64 = 1_000_000; // notional == size
    let req: i128 = 100_000_000_000;
    // CONTROL: no band -> full fill at 30 + ceil(1e4*1e11/9e11) = 1142 bps (> 500)
    let (r0, _) = env.call(&lp, &ctx, &Call::new(1, O, req)).unwrap();
    assert_eq!(r0.exec_size, req);
    let t0 = total_bps(O, r0.exec_price_e6, true);
    assert_eq!(t0, 30 + (10_000u128 * 100_000_000_000).div_ceil(900_000_000_000));
    assert!(t0 > 500);
    // band 500 -> clipped to the budget-inverse fill, quote within the band
    let (r, _) = env
        .call(&lp, &ctx, &Call::new(2, O, req).ext(ext_band(Some(500))))
        .unwrap();
    let n_max = 470u128 * 1_000_000_000_000 / (10_000 + 470);
    assert_eq!(r.exec_size as u128, n_max);
    assert_eq!(r.flags & 0xff, FLAG_VALID | FLAG_PARTIAL_OK);
    assert!(total_bps(O, r.exec_price_e6, true) <= 500);
    // band below the fixed part (30) -> zero fill at oracle
    let (r, _) = env
        .call(&lp, &ctx, &Call::new(3, O, req).ext(ext_band(Some(29))))
        .unwrap();
    assert_eq!(r.exec_size, 0);
    assert_eq!(r.exec_price_e6, O);
}
