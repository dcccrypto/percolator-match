//! P2 matcher v2 — native mechanism tests. Every mechanism is paired with a NEGATIVE
//! CONTROL: the same setup with the one mechanism input changed, showing the outcome flips
//! because of that input and not something else.

use std::cell::Cell;

use percolator_match::v2::{
    self, adaptive_fee_bps, default_config_for_kind2, CallExt, V2Block, V2Config,
    ERR_ASSET_MISMATCH, ERR_MARK_SLOT_IN_FUTURE, ERR_OWNER_PROOF_MISMATCH, ERR_STALE_MARK,
    V2_FLAG_STALE_ALLOW_REDUCING,
};
use percolator_match::vamm::{
    self, apply_fill, encode_configure, execute_leg, InitParams, LegOut, MatcherCtx, MatcherKind,
    OwnerProof, SetParams, MATCHER_MAGIC, MATCHER_VERSION,
};
use percolator_match::{
    MatcherCall, MatcherReturn, CTX_VAMM_OFFSET, FLAG_PARTIAL_OK, FLAG_REQUESTED_FEE_MASK,
    FLAG_VALID, MATCHER_CONTEXT_LEN,
};
use solana_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};

const LP_ID: u64 = 42;
const PX: u64 = 100_000_000; // $100

fn core_ctx(kind: u8) -> MatcherCtx {
    MatcherCtx {
        magic: MATCHER_MAGIC,
        version: MATCHER_VERSION,
        kind,
        _pad0: [0; 3],
        lp_pda: [7; 32],
        trading_fee_bps: 10,
        base_spread_bps: 20,
        max_total_bps: 400,
        impact_k_bps: if kind == 1 { 100 } else { 0 },
        liquidity_notional_e6: 1_000_000_000_000,
        max_fill_abs: 1_000_000_000,
        inventory_base: 0,
        last_oracle_price_e6: 0,
        last_exec_price_e6: 0,
        max_inventory_abs: 0,
        insurance_accrued_e6: 0,
        fee_to_insurance_bps: 0,
        skew_spread_mult_bps: 0,
        _new_pad: [0; 4],
        lp_account_id: LP_ID,
        insurance_fee_remainder_e6: 0,
        backing_fee_cap_bps: 0,
        _reserved: [0; 78],
    }
}

/// Kind 2 with impact and skew OFF and a pinned fee (lo == hi == cold), so single
/// mechanisms can be switched on one at a time.
fn kind2_plain(fee: u16) -> MatcherCtx {
    let mut c = core_ctx(2);
    let cfg = V2Config {
        fee_lo_bps: fee,
        fee_hi_bps: fee,
        fee_cold_bps: fee,
        vol_alpha_bps: 1000,
        vol_warmup: 0,
        vol_move_cap_10bps: 100,
        vol_ref_slots: 10,
        ..V2Config::default()
    };
    c.set_v2_block(&V2Block::fresh(cfg));
    c.validate().expect("kind2_plain valid");
    c
}

/// Kind 1 carrying a v2 block with ONLY stale-guard fields.
fn kind1_guarded(max_age: u16, observed: u16, flags: u8) -> MatcherCtx {
    let mut c = core_ctx(1);
    let cfg = V2Config {
        flags,
        max_mark_age_slots: max_age,
        observed_stale_slots: observed,
        ..V2Config::default()
    };
    c.set_v2_block(&V2Block::fresh(cfg));
    c.validate().expect("kind1_guarded valid");
    c
}

fn call(price: u64, size: i128) -> MatcherCall {
    call_asset(price, size, 0)
}

fn call_asset(price: u64, size: i128, asset: u16) -> MatcherCall {
    MatcherCall {
        req_id: 1,
        asset_index: asset,
        lp_account_id: LP_ID,
        oracle_price_e6: price,
        req_size: size,
    }
}

fn ext_headroom(h: u64) -> CallExt {
    CallExt {
        headroom_q: Some(h),
        ..CallExt::default()
    }
}

fn ext_mark(slot: u64) -> CallExt {
    CallExt {
        mark_slot: Some(slot),
        ..CallExt::default()
    }
}

fn leg(
    ctx: &mut MatcherCtx,
    c: &MatcherCall,
    e: &CallExt,
    now: u64,
) -> Result<LegOut, ProgramError> {
    let out = execute_leg(ctx, c, e, Some(now), 0)?;
    apply_fill(ctx, &out, c.oracle_price_e6)?;
    Ok(out)
}

// -----------------------------------------------------------------------------
// Call extension wire
// -----------------------------------------------------------------------------

#[test]
fn ext_roundtrip_and_legacy() {
    let e = CallExt {
        headroom_q: Some(123),
        mark_slot: Some(456),
        accepts_fee_request: true,
    };
    assert_eq!(CallExt::parse(&e.encode()).unwrap(), e);
    assert_eq!(CallExt::parse(&[0u8; 24]).unwrap(), CallExt::default());
    assert!(CallExt::default().is_legacy());
    assert_eq!(CallExt::default().encode(), [0u8; 24]);
}

#[test]
fn neg_ext_malformed_rejected() {
    let good = ext_headroom(5).encode();
    assert!(CallExt::parse(&good).is_ok(), "control: well-formed parses");
    let mut b = good;
    b[0] = 2;
    assert!(CallExt::parse(&b).is_err(), "unknown version");
    let mut b = good;
    b[1] |= 0x08;
    assert!(CallExt::parse(&b).is_err(), "unknown flag bit 3");
    let mut b = good;
    b[2] = 1;
    assert!(CallExt::parse(&b).is_err(), "reserved 2..4");
    let mut b = good;
    b[23] = 1;
    assert!(CallExt::parse(&b).is_err(), "reserved 20..24");
    let mut b = good;
    b[4] = 9; // mark_slot bytes without MARK_SLOT flag
    assert!(CallExt::parse(&b).is_err(), "field without flag");
    let mut b = [0u8; 24];
    b[10] = 1; // legacy with a stray byte
    assert!(CallExt::parse(&b).is_err(), "legacy must be all zero");
}

#[test]
fn matcher_call_parse_accepts_ext_v1_and_rejects_garbage() {
    let mut data = [0u8; 67];
    data[19..27].copy_from_slice(&PX.to_le_bytes());
    data[43..67].copy_from_slice(&ext_headroom(77).encode());
    assert!(MatcherCall::parse(&data).is_ok());
    assert_eq!(MatcherCall::parse_ext(&data).unwrap().headroom_q, Some(77));
    data[43] = 0xFF;
    assert!(
        MatcherCall::parse(&data).is_err(),
        "0xFF version still rejected (v1 behaviour)"
    );
}

// -----------------------------------------------------------------------------
// Headroom (all kinds)
// -----------------------------------------------------------------------------

#[test]
fn headroom_clips_kind1_with_partial_flag_and_control() {
    let base = core_ctx(1);
    // control: legacy call fills fully
    let mut c0 = base;
    let full = leg(&mut c0, &call(PX, 1000), &CallExt::default(), 0).unwrap();
    assert_eq!(full.exec_size, 1000);
    assert_eq!(full.flags, FLAG_VALID);
    // mechanism: headroom 100 clips
    let mut c1 = base;
    let clipped = leg(&mut c1, &call(PX, 1000), &ext_headroom(100), 0).unwrap();
    assert_eq!(clipped.exec_size, 100);
    assert_eq!(clipped.flags, FLAG_VALID | FLAG_PARTIAL_OK);
    // the clipped leg is priced exactly like an unclipped request of the same size
    let mut c2 = base;
    let same = leg(&mut c2, &call(PX, 100), &CallExt::default(), 0).unwrap();
    assert_eq!(clipped.exec_price_e6, same.exec_price_e6);
    // headroom larger than the request: no clip
    let mut c3 = base;
    let big = leg(&mut c3, &call(PX, -1000), &ext_headroom(u64::MAX), 0).unwrap();
    assert_eq!(big.exec_size, -1000);
    assert_eq!(big.flags, FLAG_VALID);
}

#[test]
fn headroom_zero_is_zero_fill_at_oracle() {
    for kind in [0u8, 1, 2] {
        let mut c = if kind == 2 {
            kind2_plain(30)
        } else {
            core_ctx(kind)
        };
        let out = leg(&mut c, &call(PX, 500), &ext_headroom(0), 10).unwrap();
        assert_eq!(out.exec_size, 0, "kind {kind}");
        assert_eq!(
            out.exec_price_e6, PX,
            "zero-fill must echo oracle (wrapper rule)"
        );
        assert_eq!(out.flags, FLAG_VALID | FLAG_PARTIAL_OK);
        assert_eq!(c.inventory_base, 0);
    }
}

#[test]
fn headroom_used_is_subtracted() {
    let mut c = core_ctx(0);
    let out = execute_leg(&mut c, &call(PX, 1000), &ext_headroom(300), None, 250).unwrap();
    assert_eq!(out.exec_size, 50);
    let out = execute_leg(&mut c, &call(PX, 1000), &ext_headroom(300), None, 300).unwrap();
    assert_eq!(out.exec_size, 0);
}

// -----------------------------------------------------------------------------
// Stale mark (authoritative mark_slot)
// -----------------------------------------------------------------------------

#[test]
fn stale_mark_slot_refused_and_controls() {
    let base = kind1_guarded(100, 0, 0);
    let now = 1_000;
    // control: age == limit fills
    let mut c = base;
    assert!(leg(&mut c, &call(PX, 10), &ext_mark(now - 100), now).is_ok());
    // mechanism: age limit+1 refused, ctx untouched
    let mut c = base;
    let before = c;
    let err = leg(&mut c, &call(PX, 10), &ext_mark(now - 101), now).unwrap_err();
    assert_eq!(err, ProgramError::Custom(ERR_STALE_MARK));
    assert_eq!(
        format!("{before:?}"),
        format!("{c:?}"),
        "refusal must not mutate ctx"
    );
    // future mark slot
    let mut c = base;
    let err = leg(&mut c, &call(PX, 10), &ext_mark(now + 1), now).unwrap_err();
    assert_eq!(err, ProgramError::Custom(ERR_MARK_SLOT_IN_FUTURE));
    // control: without MARK_SLOT in the extension the authoritative guard cannot fire
    let mut c = base;
    assert!(leg(&mut c, &call(PX, 10), &CallExt::default(), now).is_ok());
    // control: max_mark_age 0 disables
    let mut c = kind1_guarded(0, 0, 0);
    assert!(leg(&mut c, &call(PX, 10), &ext_mark(0), 1_000_000).is_ok());
}

#[test]
fn stale_allow_reducing_clips_to_inventory() {
    let now = 5_000;
    let mut c = kind1_guarded(10, 0, V2_FLAG_STALE_ALLOW_REDUCING);
    c.inventory_base = 500; // LP long
                            // taker buys => LP sells => reduces: filled, clipped to 500
    let mut r = c;
    let out = leg(&mut r, &call(PX, 800), &ext_mark(0), now).unwrap();
    assert_eq!(out.exec_size, 500);
    assert_eq!(out.flags, FLAG_VALID | FLAG_PARTIAL_OK);
    assert_eq!(r.inventory_base, 0, "cannot flip");
    // taker sells => LP buys => increases: refused
    let mut i = c;
    assert_eq!(
        leg(&mut i, &call(PX, -10), &ext_mark(0), now).unwrap_err(),
        ProgramError::Custom(ERR_STALE_MARK)
    );
    // negative control: without the flag, the reducing trade is refused too
    let mut n = kind1_guarded(10, 0, 0);
    n.inventory_base = 500;
    assert_eq!(
        leg(&mut n, &call(PX, 800), &ext_mark(0), now).unwrap_err(),
        ProgramError::Custom(ERR_STALE_MARK)
    );
}

// -----------------------------------------------------------------------------
// Observed-staleness fallback
// -----------------------------------------------------------------------------

#[test]
fn observed_stale_refuses_unchanged_price_and_controls() {
    let mut c = kind1_guarded(0, 100, 0);
    let e = CallExt::default();
    assert!(
        leg(&mut c, &call(PX, 1), &e, 1_000).is_ok(),
        "first sight records"
    );
    assert!(
        leg(&mut c, &call(PX, 1), &e, 1_100).is_ok(),
        "age == limit ok"
    );
    let mut stale = c;
    assert_eq!(
        leg(&mut stale, &call(PX, 1), &e, 1_101).unwrap_err(),
        ProgramError::Custom(ERR_STALE_MARK)
    );
    // control: the price moved by one unit -> fresh
    let mut moved = c;
    assert!(leg(&mut moved, &call(PX + 1, 1), &e, 1_101).is_ok());
    // control: fallback disabled
    let mut off = kind1_guarded(0, 0, 0);
    assert!(leg(&mut off, &call(PX, 1), &e, 1_000).is_ok());
    assert!(leg(&mut off, &call(PX, 1), &e, 900_000).is_ok());
}

// -----------------------------------------------------------------------------
// Asset binding
// -----------------------------------------------------------------------------

#[test]
fn kind2_binds_asset_and_control() {
    let mut c = kind2_plain(30);
    assert!(leg(&mut c, &call_asset(PX, 1, 3), &CallExt::default(), 10).is_ok());
    assert_eq!(
        leg(&mut c, &call_asset(PX, 1, 4), &CallExt::default(), 20).unwrap_err(),
        ProgramError::Custom(ERR_ASSET_MISMATCH)
    );
    assert!(leg(&mut c, &call_asset(PX, 1, 3), &CallExt::default(), 30).is_ok());
    // control: kind 1 with a guard-less block does not bind
    let mut k1 = kind1_guarded(50, 0, 0);
    assert!(leg(&mut k1, &call_asset(PX, 1, 3), &CallExt::default(), 10).is_ok());
    assert!(leg(&mut k1, &call_asset(PX, 1, 4), &CallExt::default(), 10).is_ok());
}

// -----------------------------------------------------------------------------
// Adaptive fee
// -----------------------------------------------------------------------------

fn adaptive_ctx() -> MatcherCtx {
    let mut c = core_ctx(2);
    let cfg = V2Config {
        fee_lo_bps: 20,
        fee_hi_bps: 150,
        fee_cold_bps: 80,
        vol_a_milli: 1000,
        vol_b_den: 200,
        vol_alpha_bps: 3000,
        vol_warmup: 3,
        vol_move_cap_10bps: 100,
        vol_ref_slots: 10,
        ..V2Config::default()
    };
    c.set_v2_block(&V2Block::fresh(cfg));
    c.validate().unwrap();
    c
}

fn fee_of(c: &MatcherCtx) -> u128 {
    let b = c.v2_block().unwrap();
    adaptive_fee_bps(&b.cfg, &b.st)
}

#[test]
fn adaptive_fee_cold_then_tracks_vol_with_control() {
    let mut vol = adaptive_ctx();
    let mut calm = adaptive_ctx();
    assert_eq!(fee_of(&vol), 80, "cold fee before warmup");
    let e = CallExt::default();
    for i in 0..30u64 {
        let slot = 100 + i * 10;
        let p_vol = if i % 2 == 0 { PX } else { PX * 102 / 100 };
        leg(&mut vol, &call(p_vol, 1), &e, slot).unwrap();
        leg(&mut calm, &call(PX, 1), &e, slot).unwrap();
    }
    let fv = fee_of(&vol);
    let fc = fee_of(&calm);
    assert_eq!(fc, 20, "negative control: constant price -> fee floor");
    assert!(fv > fc, "volatile path raises the fee: {fv} vs {fc}");
    assert!((20..=150).contains(&fv));
    // the fee is actually in the quote: probe a tiny buy on each
    let pv = execute_leg(&mut vol.clone(), &call(PX, 1), &e, Some(10_000), 0).unwrap();
    let pc = execute_leg(&mut calm.clone(), &call(PX, 1), &e, Some(10_000), 0).unwrap();
    assert!(pv.exec_price_e6 > pc.exec_price_e6);
}

#[test]
fn adaptive_fee_is_in_price_before_warmup() {
    let mut c = adaptive_ctx();
    let out = leg(&mut c, &call(PX, 1), &CallExt::default(), 5).unwrap();
    // base 20 + cold 80 = 100 bps, ceil for buys
    assert_eq!(out.exec_price_e6, PX + PX / 100);
    assert_eq!(out.fee_bps, 80);
}

// -----------------------------------------------------------------------------
// Constant-product impact
// -----------------------------------------------------------------------------

#[test]
fn cp_impact_monotone_and_size_clip_with_control() {
    let mut c = kind2_plain(30);
    c.impact_k_bps = 10_000; // exact CP
    c.liquidity_notional_e6 = 1_000_000_000; // $1,000 depth
    c.validate().unwrap();
    let e = CallExt::default();
    let mut last = 0u64;
    for sz in [1i128, 10, 100, 1_000, 10_000, 100_000, 500_000, 1_000_000] {
        let out = execute_leg(&mut c.clone(), &call(PX, sz), &e, Some(1), 0).unwrap();
        assert!(
            out.exec_price_e6 >= last,
            "buy price must not fall with size"
        );
        last = out.exec_price_e6;
        if out.exec_size < sz {
            assert_eq!(out.flags & FLAG_PARTIAL_OK, FLAG_PARTIAL_OK);
        }
        let total = (out.exec_price_e6 - PX) as u128 * 10_000 / PX as u128;
        assert!(total <= c.max_total_bps as u128 + 1);
    }
    // a size far beyond depth is clipped, not price-clamped
    let huge = execute_leg(&mut c.clone(), &call(PX, 1_000_000_000), &e, Some(1), 0).unwrap();
    assert!(huge.exec_size > 0 && huge.exec_size < 1_000_000_000);
    // control: impact off -> identical price at every size
    let mut flat = kind2_plain(30);
    let p1 = execute_leg(&mut flat.clone(), &call(PX, 1), &e, Some(1), 0).unwrap();
    let p2 = execute_leg(&mut flat, &call(PX, 1_000_000), &e, Some(1), 0).unwrap();
    assert_eq!(p1.exec_price_e6, p2.exec_price_e6);
}

// -----------------------------------------------------------------------------
// Skew surcharge / thin-side rebate
// -----------------------------------------------------------------------------

fn skew_ctx(s: u16, r: u16) -> MatcherCtx {
    let mut c = kind2_plain(30);
    c.skew_spread_mult_bps = s;
    let mut b = c.v2_block().unwrap();
    b.cfg.thin_rebate_mult_bps = r;
    b.cfg.skew_cap_bps = 300;
    b.cfg.rebate_cap_bps = 150;
    b.cfg.skew_ref_inventory = 100_000;
    c.set_v2_block(&b);
    c.validate().unwrap();
    c
}

#[test]
fn skew_surcharge_and_rebate_with_control() {
    let e = CallExt::default();
    let q = |mut c: MatcherCtx, inv: i128, sz: i128| {
        c.inventory_base = inv;
        execute_leg(&mut c, &call(PX, sz), &e, Some(1), 0)
            .unwrap()
            .exec_price_e6
    };
    let on = skew_ctx(200, 100);
    let off = skew_ctx(0, 0);
    // LP short 50k. Taker buy worsens -> surcharge; taker sell reduces -> rebate.
    let buy_flat = q(on, 0, 1_000);
    let buy_short = q(on, -50_000, 1_000);
    assert!(buy_short > buy_flat, "surcharge when worsening");
    let sell_flat = q(on, 0, -1_000);
    let sell_short = q(on, -50_000, -1_000);
    assert!(
        sell_short > sell_flat,
        "rebate: seller gets a better (higher) bid"
    );
    assert!(sell_short <= PX, "rebate never crosses the oracle");
    assert!(buy_short >= PX);
    // control: skew off -> inventory has no effect
    assert_eq!(q(off, 0, 1_000), q(off, -50_000, 1_000));
    assert_eq!(q(off, 0, -1_000), q(off, -50_000, -1_000));
}

#[test]
fn validate_rejects_rebate_steeper_than_surcharge() {
    let ok = skew_ctx(100, 100);
    assert!(ok.validate().is_ok(), "control: r == s allowed");
    let mut bad = ok;
    let mut b = bad.v2_block().unwrap();
    b.cfg.thin_rebate_mult_bps = 101;
    bad.set_v2_block(&b);
    assert!(bad.validate().is_err());
}

// -----------------------------------------------------------------------------
// validate_config rules
// -----------------------------------------------------------------------------

#[test]
fn validate_config_rules() {
    let good = kind2_plain(30);
    assert!(good.validate().is_ok());
    let mutate = |f: &dyn Fn(&mut V2Config)| {
        let mut c = good;
        let mut b = c.v2_block().unwrap();
        f(&mut b.cfg);
        c.set_v2_block(&b);
        c.validate()
    };
    assert!(mutate(&|c| c.fee_lo_bps = 31).is_err(), "lo > cold");
    assert!(mutate(&|c| c.fee_hi_bps = 29).is_err(), "hi < cold");
    assert!(mutate(&|c| {
        c.fee_hi_bps = 1001;
        c.fee_cold_bps = 1001;
        c.fee_lo_bps = 1001
    })
    .is_err());
    assert!(mutate(&|c| c.vol_alpha_bps = 0).is_err());
    assert!(mutate(&|c| c.vol_ref_slots = 0).is_err());
    assert!(mutate(&|c| c.vol_move_cap_10bps = 0).is_err());
    assert!(mutate(&|c| c.skew_cap_bps = 5001).is_err());
    assert!(mutate(&|c| c.flags = 0x80).is_err());
    // base + fee_hi > max_total
    let mut c = good;
    c.max_total_bps = 49;
    assert!(c.validate().is_err());
    // kind 2 without a block
    let mut c = core_ctx(2);
    c._reserved = [0; 78];
    assert!(c.validate().is_err());
    // kind 1 block with pricing fields set
    let mut c = kind1_guarded(10, 0, 0);
    let mut b = c.v2_block().unwrap();
    b.cfg.fee_lo_bps = 5;
    c.set_v2_block(&b);
    assert!(c.validate().is_err());
    // garbage reserved bytes (no valid block marker)
    let mut c = core_ctx(1);
    c._reserved[5] = 1;
    assert!(c.validate().is_err());
}

// -----------------------------------------------------------------------------
// Instruction-level: init, tag 5, fee-request bits, clock isolation
// -----------------------------------------------------------------------------

thread_local! {
    static SLOT: Cell<u64> = const { Cell::new(0) };
}
fn test_slot() -> Result<u64, ProgramError> {
    Ok(SLOT.with(|s| s.get()))
}
fn panicking_slot() -> Result<u64, ProgramError> {
    panic!("legacy path must not read the clock")
}

struct Acc {
    key: Pubkey,
    lamports: u64,
    data: Vec<u8>,
}

fn ctx_bytes(c: &MatcherCtx) -> Vec<u8> {
    let mut d = vec![0u8; MATCHER_CONTEXT_LEN];
    c.write_to(&mut d[CTX_VAMM_OFFSET..]).unwrap();
    d
}

fn call_bytes(price: u64, size: i128, ext: &CallExt) -> [u8; 67] {
    let mut d = [0u8; 67];
    d[1..9].copy_from_slice(&1u64.to_le_bytes());
    d[11..19].copy_from_slice(&LP_ID.to_le_bytes());
    d[19..27].copy_from_slice(&price.to_le_bytes());
    d[27..43].copy_from_slice(&size.to_le_bytes());
    d[43..67].copy_from_slice(&ext.encode());
    d
}

fn run_call(
    prog: &Pubkey,
    lp: &Pubkey,
    ctx: &mut Acc,
    data: &[u8],
    clock: fn() -> Result<u64, ProgramError>,
) -> Result<MatcherReturn, ProgramError> {
    let mut lpl = 0u64;
    let lp_ai = AccountInfo::new(lp, true, false, &mut lpl, &mut [], prog, false, 0);
    let ctx_ai = AccountInfo::new(
        &ctx.key,
        false,
        true,
        &mut ctx.lamports,
        &mut ctx.data,
        prog,
        false,
        0,
    );
    vamm::process_call_with_clock(&lp_ai, &ctx_ai, data, clock)?;
    let d = &ctx.data;
    Ok(MatcherReturn {
        abi_version: u32::from_le_bytes(d[0..4].try_into().unwrap()),
        flags: u32::from_le_bytes(d[4..8].try_into().unwrap()),
        exec_price_e6: u64::from_le_bytes(d[8..16].try_into().unwrap()),
        exec_size: i128::from_le_bytes(d[16..32].try_into().unwrap()),
        req_id: u64::from_le_bytes(d[32..40].try_into().unwrap()),
        lp_account_id: u64::from_le_bytes(d[40..48].try_into().unwrap()),
        oracle_price_e6: u64::from_le_bytes(d[48..56].try_into().unwrap()),
        asset_index: u64::from_le_bytes(d[56..64].try_into().unwrap()),
    })
}

#[test]
fn legacy_context_never_reads_clock() {
    let prog = Pubkey::new_unique();
    let lp = Pubkey::new_from_array([7; 32]);
    for kind in [0u8, 1] {
        let mut ctx = Acc {
            key: Pubkey::new_unique(),
            lamports: 1,
            data: ctx_bytes(&core_ctx(kind)),
        };
        // headroom ext on a block-less ctx: still no clock
        let r = run_call(
            &prog,
            &lp,
            &mut ctx,
            &call_bytes(PX, 5, &ext_headroom(3)),
            panicking_slot,
        )
        .unwrap();
        assert_eq!(r.exec_size, 3);
    }
    // control: a ctx WITH a v2 block does read the clock
    let mut ctx = Acc {
        key: Pubkey::new_unique(),
        lamports: 1,
        data: ctx_bytes(&kind1_guarded(10, 0, 0)),
    };
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = run_call(
            &prog,
            &lp,
            &mut ctx,
            &call_bytes(PX, 5, &CallExt::default()),
            panicking_slot,
        );
    }));
    assert!(caught.is_err(), "v2-block ctx must consult the clock");
}

#[test]
fn fee_request_bits_only_when_negotiated() {
    let prog = Pubkey::new_unique();
    let lp = Pubkey::new_from_array([7; 32]);
    SLOT.with(|s| s.set(10));
    let fresh = || Acc {
        key: Pubkey::new_unique(),
        lamports: 1,
        data: ctx_bytes(&kind2_plain(30)),
    };
    let ask = CallExt {
        accepts_fee_request: true,
        ..CallExt::default()
    };
    // mechanism
    let r = run_call(
        &prog,
        &lp,
        &mut fresh(),
        &call_bytes(PX, 5, &ask),
        test_slot,
    )
    .unwrap();
    assert_eq!(r.requested_fee_bps(), 50, "base 20 + fee 30");
    // control: legacy ext -> no bits, flags within v18.2 KNOWN_FLAGS
    let r = run_call(
        &prog,
        &lp,
        &mut fresh(),
        &call_bytes(PX, 5, &CallExt::default()),
        test_slot,
    )
    .unwrap();
    assert_eq!(r.flags & FLAG_REQUESTED_FEE_MASK, 0);
    let known = FLAG_VALID | FLAG_PARTIAL_OK | 4 | percolator_match::FLAG_BACKING_FEE_CAP_MASK;
    assert_eq!(r.flags & !known, 0);
    // control: ext present but not negotiated
    let r = run_call(
        &prog,
        &lp,
        &mut fresh(),
        &call_bytes(PX, 5, &ext_headroom(100)),
        test_slot,
    )
    .unwrap();
    assert_eq!(r.flags & FLAG_REQUESTED_FEE_MASK, 0);
    // control: zero fill never requests a fee
    let zf = CallExt {
        headroom_q: Some(0),
        accepts_fee_request: true,
        ..CallExt::default()
    };
    let r = run_call(&prog, &lp, &mut fresh(), &call_bytes(PX, 5, &zf), test_slot).unwrap();
    assert_eq!(r.exec_size, 0);
    assert_eq!(r.flags & FLAG_REQUESTED_FEE_MASK, 0);
}

#[test]
fn init_kind2_gets_valid_defaults_kind1_stays_v1_identical() {
    let prog = Pubkey::new_unique();
    let lp = Pubkey::new_unique();
    let mk = |kind: u8| InitParams {
        kind,
        trading_fee_bps: 10,
        base_spread_bps: 50,
        max_total_bps: 200,
        impact_k_bps: 0,
        liquidity_notional_e6: 1_000_000,
        max_fill_abs: 1_000,
        max_inventory_abs: 4_000,
        fee_to_insurance_bps: 0,
        skew_spread_mult_bps: 50,
        lp_account_id: 9,
    };
    for kind in [1u8, 2] {
        let mut data = vec![0u8; MATCHER_CONTEXT_LEN];
        let mut l1 = 0u64;
        let mut l2 = 1u64;
        let ck = Pubkey::new_unique();
        let accs = [
            AccountInfo::new(&lp, true, false, &mut l1, &mut [], &prog, false, 0),
            AccountInfo::new(&ck, false, true, &mut l2, &mut data, &prog, false, 0),
        ];
        vamm::process_init(&prog, &accs, &mk(kind).encode()).unwrap();
        drop(accs);
        let ctx = MatcherCtx::read_from(&data[CTX_VAMM_OFFSET..]).unwrap();
        ctx.validate().unwrap();
        if kind == 1 {
            assert_eq!(ctx._reserved, [0; 78], "kind 1 init must leave v1 bytes");
            assert!(ctx.v2_block().is_none());
        } else {
            let b = ctx.v2_block().expect("kind 2 gets a block");
            let mut want = default_config_for_kind2(10, 50, 200, 50, 4_000);
            // vol_warmup is not stored: it is written into the countdown vol_warmup_left.
            assert_eq!(b.st.vol_warmup_left, want.vol_warmup);
            want.vol_warmup = 0;
            assert_eq!(b.cfg, want);
            assert!(b.cfg.fee_hi_bps as u32 + 50 <= 200);
            assert_eq!(b.cfg.skew_ref_inventory, 4_000);
        }
    }
}

fn configure(
    prog: &Pubkey,
    signer: &Pubkey,
    is_signer: bool,
    ctx: &mut Acc,
    data: &[u8],
) -> Result<(), ProgramError> {
    let mut l = 0u64;
    let accs = [
        AccountInfo::new(signer, is_signer, false, &mut l, &mut [], prog, false, 0),
        AccountInfo::new(
            &ctx.key,
            false,
            true,
            &mut ctx.lamports,
            &mut ctx.data,
            prog,
            false,
            0,
        ),
    ];
    vamm::process_configure(prog, &accs, data)
}

fn read_ctx(a: &Acc) -> MatcherCtx {
    MatcherCtx::read_from(&a.data[CTX_VAMM_OFFSET..]).unwrap()
}

#[test]
fn tag5_lp_pda_mode_and_negatives() {
    let prog = Pubkey::new_unique();
    let lp = Pubkey::new_from_array([7; 32]);
    let mut ctx = Acc {
        key: Pubkey::new_unique(),
        lamports: 1,
        data: ctx_bytes(&core_ctx(1)),
    };
    let op0 = |cap: u16| {
        let mut p = vec![vamm::CONFIGURE_OP_BACKING_FEE_CAP];
        p.extend_from_slice(&cap.to_le_bytes());
        encode_configure(None, &p)
    };
    configure(&prog, &lp, true, &mut ctx, &op0(250)).unwrap();
    assert_eq!(read_ctx(&ctx).backing_fee_cap_bps, 250);
    let other = Pubkey::new_unique();
    assert!(
        configure(&prog, &other, true, &mut ctx, &op0(1)).is_err(),
        "wrong signer"
    );
    assert_eq!(
        configure(&prog, &lp, false, &mut ctx, &op0(1)).unwrap_err(),
        ProgramError::MissingRequiredSignature
    );
    assert!(configure(&prog, &lp, true, &mut ctx, &op0(10_001)).is_err());
    assert_eq!(
        read_ctx(&ctx).backing_fee_cap_bps,
        250,
        "failed configs change nothing"
    );
}

#[test]
fn tag5_owner_proof_mode_and_negatives() {
    let prog = Pubkey::new_unique(); // matcher program id
    let wrapper = Pubkey::new_unique();
    let market = Pubkey::new_unique();
    let portfolio = Pubkey::new_unique();
    let owner = Pubkey::new_unique();
    let ctx_key = Pubkey::new_unique();
    let (delegate, bump) = Pubkey::find_program_address(
        &[
            b"matcher",
            market.as_ref(),
            portfolio.as_ref(),
            owner.as_ref(),
            prog.as_ref(),
            ctx_key.as_ref(),
        ],
        &wrapper,
    );
    let mut c = core_ctx(0);
    c.lp_pda = delegate.to_bytes();
    let mut ctx = Acc {
        key: ctx_key,
        lamports: 1,
        data: ctx_bytes(&c),
    };
    let proof = OwnerProof {
        wrapper_program_id: wrapper.to_bytes(),
        market: market.to_bytes(),
        lp_portfolio: portfolio.to_bytes(),
        bump,
    };
    let op0 = |p: &OwnerProof, cap: u16| {
        let mut v = vec![vamm::CONFIGURE_OP_BACKING_FEE_CAP];
        v.extend_from_slice(&cap.to_le_bytes());
        encode_configure(Some(p), &v)
    };
    configure(&prog, &owner, true, &mut ctx, &op0(&proof, 777)).unwrap();
    assert_eq!(read_ctx(&ctx).backing_fee_cap_bps, 777);
    assert_eq!(u16::from_le_bytes([ctx.data[240], ctx.data[241]]), 777);

    let bad = ProgramError::Custom(ERR_OWNER_PROOF_MISMATCH);
    let intruder = Pubkey::new_unique();
    assert_eq!(
        configure(&prog, &intruder, true, &mut ctx, &op0(&proof, 1)).unwrap_err(),
        bad
    );
    let mut p = proof;
    p.market = Pubkey::new_unique().to_bytes();
    assert_eq!(
        configure(&prog, &owner, true, &mut ctx, &op0(&p, 1)).unwrap_err(),
        bad
    );
    let mut p = proof;
    p.lp_portfolio = Pubkey::new_unique().to_bytes();
    assert_eq!(
        configure(&prog, &owner, true, &mut ctx, &op0(&p, 1)).unwrap_err(),
        bad
    );
    let mut p = proof;
    p.wrapper_program_id = Pubkey::new_unique().to_bytes();
    assert_eq!(
        configure(&prog, &owner, true, &mut ctx, &op0(&p, 1)).unwrap_err(),
        bad
    );
    let mut p = proof;
    p.bump = bump.wrapping_sub(1);
    assert!(configure(&prog, &owner, true, &mut ctx, &op0(&p, 1)).is_err());
    assert_eq!(
        configure(&prog, &owner, false, &mut ctx, &op0(&proof, 1)).unwrap_err(),
        ProgramError::MissingRequiredSignature
    );
    // lp_pda mode cannot be used by the owner on a PDA-bound ctx
    let mut v = vec![vamm::CONFIGURE_OP_BACKING_FEE_CAP];
    v.extend_from_slice(&1u16.to_le_bytes());
    assert!(configure(&prog, &owner, true, &mut ctx, &encode_configure(None, &v)).is_err());
    assert_eq!(read_ctx(&ctx).backing_fee_cap_bps, 777);
}

#[test]
fn tag5_set_params_switches_kind_and_preserves_state() {
    let prog = Pubkey::new_unique();
    let lp = Pubkey::new_from_array([7; 32]);
    let mut c = core_ctx(1);
    c.inventory_base = -1234;
    c.insurance_accrued_e6 = 99;
    c.backing_fee_cap_bps = 42;
    let mut ctx = Acc {
        key: Pubkey::new_unique(),
        lamports: 1,
        data: ctx_bytes(&c),
    };
    let cfg = default_config_for_kind2(10, 20, 400, 100, 10_000);
    let sp = SetParams {
        kind: MatcherKind::Adaptive as u8,
        trading_fee_bps: 0,
        base_spread_bps: 20,
        max_total_bps: 400,
        impact_k_bps: 10_000,
        liquidity_notional_e6: 5_000_000_000,
        max_fill_abs: u128::MAX,
        max_inventory_abs: 10_000,
        fee_to_insurance_bps: 0,
        skew_spread_mult_bps: 100,
        enable_v2: true,
        v2: cfg,
    };
    assert_eq!(SetParams::parse(&sp.encode()).unwrap(), sp);
    let mut payload = vec![vamm::CONFIGURE_OP_SET_PARAMS];
    payload.extend_from_slice(&sp.encode());
    configure(
        &prog,
        &lp,
        true,
        &mut ctx,
        &encode_configure(None, &payload),
    )
    .unwrap();
    let after = read_ctx(&ctx);
    assert_eq!(after.kind, 2);
    assert_eq!(after.inventory_base, -1234);
    assert_eq!(after.insurance_accrued_e6, 99);
    assert_eq!(after.backing_fee_cap_bps, 42);
    assert_eq!(
        after.max_fill_abs,
        i128::MAX as u128,
        "u128::MAX clamped like init"
    );
    assert_eq!(after.v2_block().unwrap().cfg.fee_lo_bps, cfg.fee_lo_bps);

    // negative: invalid params (fee_lo > fee_hi) rejected, ctx unchanged
    let snapshot = ctx.data.clone();
    let mut bad = sp;
    bad.v2.fee_lo_bps = bad.v2.fee_hi_bps + 1;
    let mut payload = vec![vamm::CONFIGURE_OP_SET_PARAMS];
    payload.extend_from_slice(&bad.encode());
    assert!(configure(
        &prog,
        &lp,
        true,
        &mut ctx,
        &encode_configure(None, &payload)
    )
    .is_err());
    assert_eq!(ctx.data, snapshot);

    // disabling v2 on kind 2 is invalid; on kind 1 it restores the v1 layout
    let mut off = sp;
    off.enable_v2 = false;
    let mut payload = vec![vamm::CONFIGURE_OP_SET_PARAMS];
    payload.extend_from_slice(&off.encode());
    assert!(configure(
        &prog,
        &lp,
        true,
        &mut ctx,
        &encode_configure(None, &payload)
    )
    .is_err());
    off.kind = 1;
    off.impact_k_bps = 100;
    let mut payload = vec![vamm::CONFIGURE_OP_SET_PARAMS];
    payload.extend_from_slice(&off.encode());
    configure(
        &prog,
        &lp,
        true,
        &mut ctx,
        &encode_configure(None, &payload),
    )
    .unwrap();
    assert!(read_ctx(&ctx).v2_block().is_none());
    assert_eq!(read_ctx(&ctx)._reserved, [0; 78]);
}

#[test]
fn v2_ctx_refusal_leaves_account_bytes_untouched() {
    let prog = Pubkey::new_unique();
    let lp = Pubkey::new_from_array([7; 32]);
    SLOT.with(|s| s.set(10_000));
    let mut ctx = Acc {
        key: Pubkey::new_unique(),
        lamports: 1,
        data: ctx_bytes(&kind1_guarded(100, 0, 0)),
    };
    let before = ctx.data.clone();
    let err = run_call(
        &prog,
        &lp,
        &mut ctx,
        &call_bytes(PX, 5, &ext_mark(1)),
        test_slot,
    )
    .unwrap_err();
    assert_eq!(err, ProgramError::Custom(ERR_STALE_MARK));
    assert_eq!(ctx.data, before);
    // control: fresh mark fills and writes
    let r = run_call(
        &prog,
        &lp,
        &mut ctx,
        &call_bytes(PX, 5, &ext_mark(9_950)),
        test_slot,
    )
    .unwrap();
    assert_eq!(r.exec_size, 5);
    assert_ne!(ctx.data, before);
}

#[test]
fn defaults_are_valid_across_core_params() {
    for (fee, base, max_total, skew, inv) in [
        (10u32, 50u32, 200u32, 50u16, 4_000u128),
        (0, 0, 9_000, 0, 0),
        (1000, 0, 1000, 10_000, u128::MAX),
        (5, 150, 200, 1, 1),
        (10, 200, 200, 0, 7),
    ] {
        let cfg = default_config_for_kind2(fee, base, max_total, skew, inv);
        let mut c = core_ctx(2);
        c.trading_fee_bps = fee.min(max_total - base);
        c.base_spread_bps = base;
        c.max_total_bps = max_total;
        c.skew_spread_mult_bps = skew;
        c.set_v2_block(&V2Block::fresh(cfg));
        assert!(
            c.validate().is_ok(),
            "defaults invalid for {fee},{base},{max_total},{skew},{inv}: {cfg:?}"
        );
    }
}

#[allow(dead_code)]
fn _uses(_: v2::MarkState) {}
