//! Behaviour found while writing the suite. `observed_*` tests ASSERT THE CURRENT
//! (questionable) BEHAVIOUR so the suite is green and the finding is reproducible; the doc
//! comment says what one would expect instead — if src/ is changed to fix one, that test
//! fails and should be flipped. `regression_*` tests are findings already fixed in src/.
mod common;
use common::*;
use percolator_match::v2::{CallExt, V2Config};
use percolator_match::vamm::InitParams;
use percolator_match::{FLAG_PARTIAL_OK, FLAG_VALID};

fn core(k: u32) -> InitParams {
    InitParams {
        kind: 2,
        trading_fee_bps: 0,
        base_spread_bps: 50,
        max_total_bps: 400,
        impact_k_bps: k,
        liquidity_notional_e6: 1_000_000_000_000,
        skew_spread_mult_bps: 400,
        ..init_params(0)
    }
}

fn cfg() -> V2Config {
    V2Config {
        skew_cap_bps: 300,
        skew_ref_inventory: 10_000,
        ..fixed_fee_v2(50)
    }
}

fn fill_for(k: u32, req: i128) -> (i128, u64, u32) {
    let mut env = Env::v2();
    let lp = seeded_keypair(1);
    let ctx = env.new_ctx(&lp, &init_params(2));
    env.set_params(&lp, &ctx, &set_params_from(&core(k), true, cfg()))
        .unwrap();
    env.warp(5);
    let (r, _) = env.call(&lp, &ctx, &Call::new(1, 1_000_000, req)).unwrap();
    (r.exec_size, r.exec_price_e6, r.flags)
}

/// REGRESSION for finding A (present at 49fb7dc and earlier, fixed in 203a4aa): the kind-2
/// fill must be monotone in the requested size. Before the fix, from FLAT inventory with
/// base 50 + fee 50 + skew_cap 300 == max_total 400, a 1_000_000 buy filled in full but a
/// 3_000_000 (or any larger) buy was ZERO-filled: `quote_adaptive` sized the impact
/// budget with the skew at the FULL request and refused when base+fee+skew_full >=
/// max_total. Now fill = min(request, f*) with f* independent of the request.
#[test]
fn regression_kind2_fill_monotone_in_request_when_skew_cap_binds() {
    let mut prev = 0i128;
    let mut clipped = false;
    for req in [14_000i128, 100_000, 1_000_000, 3_000_000, 10_000_000, 1_000_000_000] {
        let (f, p, fl) = fill_for(10_000, req);
        println!("req {req} -> fill {f} @ {p} flags {fl:#x}");
        assert!(f >= prev, "fill must be non-decreasing in the request ({req}: {f} < {prev})");
        assert!(f <= req);
        if f < req {
            clipped = true;
            assert_eq!(fl & 0xff, FLAG_VALID | FLAG_PARTIAL_OK);
            assert!(p <= ask(1_000_000, 400));
        }
        prev = f;
    }
    assert!(clipped, "the sweep must reach the clip");
    assert_eq!(fill_for(10_000, 1_000_000).0, 1_000_000);
}

/// REGRESSION (price clamp vs size clip with impact OFF): base 50 + fee 50 with
/// skew_cap 400 > the 300 bps of room. The surcharge alone can exceed max_total, so a huge
/// request must be SIZE-clipped (PARTIAL_OK, priced <= max_total) rather than filled in full
/// at the max_total clamp (v1's free option). CONTROL: a small request fills in full.
#[test]
fn regression_kind2_impact_zero_skew_over_room_size_clips() {
    let run = |req: i128| {
        let mut env = Env::v2();
        let lp = seeded_keypair(1);
        let ctx = env.new_ctx(&lp, &init_params(2));
        let mut c = cfg();
        c.skew_cap_bps = 400;
        env.set_params(&lp, &ctx, &set_params_from(&core(0), true, c))
            .unwrap();
        env.warp(5);
        env.call(&lp, &ctx, &Call::new(1, 1_000_000, req)).unwrap().0
    };
    let small = run(1_000);
    assert_eq!(small.exec_size, 1_000);
    let big = run(10_000_000_000);
    println!("impact 0, skew_cap 400: req 1e10 -> fill {} @ {}", big.exec_size, big.exec_price_e6);
    assert!(big.exec_size > 1_000 && big.exec_size < 10_000_000_000, "size clip");
    assert_eq!(big.flags & 0xff, FLAG_VALID | FLAG_PARTIAL_OK);
    assert!(big.exec_price_e6 <= ask(1_000_000, 400));
}

/// FINDING C: on a ctx WITHOUT a v2 block (every v1-created / kind-0/1 default ctx), the
/// call extension's mark_slot is ignored entirely — a mark_slot in the FUTURE (which the
/// v2 docs say "the wrapper never produces; fail closed") and an ancient mark_slot both
/// fill. The guard is opt-in per ctx (tag 5), so a wrapper that starts sending mark_slot
/// gets no protection from existing contexts. Documented, arguably by design.
#[test]
fn observed_mark_slot_ignored_without_v2_block() {
    let mut env = Env::v2();
    let lp = seeded_keypair(1);
    let ctx = env.new_ctx(&lp, &init_params(1));
    env.warp(1_000);
    for ms in [u64::MAX, 1_001, 0] {
        let (r, _) = env
            .call(
                &lp,
                &ctx,
                &Call::new(ms, 1_000_000, 10).ext(CallExt {
                    headroom_q: None,
                    mark_slot: Some(ms),
                    accepts_fee_request: false,
                    ..CallExt::default()
                }),
            )
            .unwrap();
        assert_eq!(r.exec_size, 10, "mark_slot {ms}");
    }
}

/// FINDING D — MITIGATED in the commit after 203a4aa: LP-REDUCING requests are exempt from
/// the size clip (fill up to |inventory| at the max_total clamp; native test
/// `saturated_fee_blocks_increasing_but_not_lp_reducing`). What this test still asserts —
/// risk-increasing fills zero-fill once the fee saturates — is the INTENDED volatility
/// circuit breaker behind the backtest's tuned-A result.
/// Original finding: (kind-2 DEFAULT config, i.e. a ctx created through the fixed 78-byte tag-2
/// payload wrapper tag 83 sends): when `max_total_bps - base_spread_bps <=
/// DEFAULT_FEE_HI_BPS`, `default_config_for_kind2` sets fee_hi = max_total - base, i.e. the
/// adaptive fee's ceiling consumes the ENTIRE room. With impact_k_bps > 0 every non-zero
/// fill has impact >= 1 bps (ceil), so once the estimator saturates the fee at fee_hi,
/// base + fee_hi + impact > max_total for every size and the ctx ZERO-FILLS EVERYTHING —
/// exactly in the volatile periods it exists for. (At 49fb7dc, where fee_cold == fee_hi for
/// room <= 80, it was also dead for the whole warmup.) CONTROL: the identical ctx retuned
/// with fee_hi = room - 10, re-warmed with the same volatile feed, fills. Expected: the
/// default (and/or validate_config) should leave headroom for impact, e.g. fee_hi <
/// max_total - base when impact_k_bps > 0.
#[test]
fn observed_kind2_default_config_dead_when_fee_saturates() {
    let p = InitParams {
        kind: 2,
        trading_fee_bps: 10,
        base_spread_bps: 20,
        max_total_bps: 100,
        impact_k_bps: 1_000,
        liquidity_notional_e6: 10_000_000_000_000,
        ..init_params(0)
    };
    let room = (p.max_total_bps - p.base_spread_bps) as u16;
    let feed = |env: &mut Env, lp: &solana_keypair::Keypair, ctx: &solana_pubkey::Pubkey, s0: u64| {
        let mut slot = s0;
        for i in 0..14u64 {
            slot += 25;
            env.warp(slot);
            let px = if i % 2 == 0 { 1_000_000 } else { 1_020_000 };
            env.call(lp, ctx, &Call::new(i, px, if i % 2 == 0 { 1 } else { -1 })).unwrap();
        }
        slot
    };
    let mut env = Env::v2();
    let lp = seeded_keypair(1);
    let ctx = env.new_ctx(&lp, &p);
    let def = env.ctx_struct(&ctx).v2_block().unwrap().cfg;
    println!("default kind-2 cfg for room {room}: lo {} cold {} hi {}", def.fee_lo_bps, def.fee_cold_bps, def.fee_hi_bps);
    assert_eq!(def.fee_hi_bps, room, "default fee_hi consumes the whole room");
    feed(&mut env, &lp, &ctx, 100);
    let (r, _) = env.call(&lp, &ctx, &Call::new(99, 1_000_000, 1)).unwrap();
    assert_eq!(r.exec_size, 0, "saturated default ctx refuses even a size-1 order");
    let (r, _) = env.call(&lp, &ctx, &Call::new(98, 1_000_000, -1)).unwrap();
    assert_eq!(r.exec_size, 0);

    // CONTROL: same ctx, only fee_hi lowered (cold/lo kept <= hi), same volatile feed.
    let mut c = def;
    c.fee_hi_bps = room - 10;
    c.fee_cold_bps = c.fee_cold_bps.min(c.fee_hi_bps);
    c.fee_lo_bps = c.fee_lo_bps.min(c.fee_cold_bps);
    c.vol_warmup = 8;
    env.set_params(&lp, &ctx, &set_params_from(&p, true, c)).unwrap();
    feed(&mut env, &lp, &ctx, 10_000);
    let (r, _) = env.call(&lp, &ctx, &Call::new(97, 1_000_000, 1)).unwrap();
    assert_eq!(r.exec_size, 1, "fee_hi below the room: fills at saturation");
    assert_eq!(r.exec_price_e6, ask(1_000_000, 20 + (room as u128 - 10) + 1));
}
