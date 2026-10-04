//! growth-v19 (2026-10-04, `~/percolator-ops/ledger/devnet-v2-growth-plan-2026-10-04.md` §2.2):
//! call extension v3 = the v2 block + the wrapper's capital-derived caps
//! (`u128 inventory_cap_q`, `u128 liquidity_notional_e6`), and the kind-1 skew unit fix.
//!
//! Rules under test:
//! * v1 / v2 / v3 parity: a v3 call whose caps do not bind returns exactly what the v2 call
//!   (and, with the same inventory, the v1 call) returns, for kinds 0, 1 and 2;
//! * every cap is `min(ctx, ext)`: never looser than the context; a context cap of 0
//!   (unlimited) takes the ext cap;
//! * `inventory_cap_q == 0` means CLOSED to LP growth (LP-reducing fills only, up to flat),
//!   NOT unlimited;
//! * a smaller `liquidity_notional_e6` (less capital) moves the quote more;
//! * wire strictness: wrong length / version / an over-i128 cap fail closed, a batch never
//!   mixes widths;
//! * kind-1 skew is bps per 100% of the inventory cap (`mult * |inv| / cap`), not per raw Q.
//!
//! Negative controls are by file copy (see the PR description): with v3 parsing disabled in
//! `vamm.rs` the cap / closed / depth tests fail; with the legacy skew formula restored the
//! skew-units test fails.

use percolator_match::v2::{self, CallExt, ExtCapsV3};
use percolator_match::vamm::{self, MatcherCtx, MATCHER_MAGIC, MATCHER_VERSION};
use percolator_match::{
    CTX_VAMM_OFFSET, MATCHER_CALL_V2_LEN, MATCHER_CALL_V3_LEN, MATCHER_CONTEXT_LEN,
};
use solana_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};

const LP_ID: u64 = 42;
const PX: u64 = 100_000_000;
const NOW: u64 = 1_000;

fn ctx(kind: u8, inventory: i128, cap: u128) -> MatcherCtx {
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
        max_fill_abs: u128::MAX >> 1,
        inventory_base: inventory,
        last_oracle_price_e6: 0,
        last_exec_price_e6: 0,
        max_inventory_abs: cap,
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

/// A kind-2 (adaptive) context with a default v2 block, skew on.
fn ctx_kind2(inventory: i128, cap: u128) -> MatcherCtx {
    let mut c = ctx(2, inventory, cap);
    c.impact_k_bps = 100;
    c.skew_spread_mult_bps = 50;
    let cfg = v2::default_config_for_kind2(10, 20, 400, 50, cap);
    let block = v2::V2Block {
        cfg,
        st: v2::V2State::default(),
    };
    c.set_v2_block(&block);
    c
}

fn clock() -> Result<u64, ProgramError> {
    Ok(NOW)
}

fn ctx_bytes(c: &MatcherCtx) -> Vec<u8> {
    let mut d = vec![0u8; MATCHER_CONTEXT_LEN];
    c.write_to(&mut d[CTX_VAMM_OFFSET..]).unwrap();
    d
}

fn head(d: &mut [u8], size: i128) {
    d[1..9].copy_from_slice(&1u64.to_le_bytes());
    d[11..19].copy_from_slice(&LP_ID.to_le_bytes());
    d[19..27].copy_from_slice(&PX.to_le_bytes());
    d[27..43].copy_from_slice(&size.to_le_bytes());
}

fn base_ext() -> CallExt {
    CallExt {
        mark_slot: Some(NOW),
        ..CallExt::default()
    }
}

fn call_v1(size: i128) -> Vec<u8> {
    let mut d = vec![0u8; 67];
    head(&mut d, size);
    d[43..67].copy_from_slice(&base_ext().encode());
    d
}

fn call_v2(size: i128, lp_pos: i128) -> Vec<u8> {
    let mut d = vec![0u8; MATCHER_CALL_V2_LEN];
    head(&mut d, size);
    let e = CallExt {
        lp_position_q: Some(lp_pos),
        ..base_ext()
    };
    d[43..83].copy_from_slice(&e.encode_v2());
    d
}

fn call_v3(size: i128, lp_pos: i128, cap: u128, liq: u128) -> Vec<u8> {
    let mut d = vec![0u8; MATCHER_CALL_V3_LEN];
    head(&mut d, size);
    let e = CallExt {
        lp_position_q: Some(lp_pos),
        ..base_ext()
    };
    d[43..115].copy_from_slice(&e.encode_v3(&ExtCapsV3 {
        inventory_cap_q: cap,
        liquidity_notional_e6: liq,
    }));
    d
}

/// Every field of the 64-byte matcher return, comparable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Ret {
    abi_version: u32,
    flags: u32,
    exec_price_e6: u64,
    exec_size: i128,
    req_id: u64,
    lp_account_id: u64,
    oracle_price_e6: u64,
    asset_index: u64,
}

fn run(c: &MatcherCtx, data: &[u8]) -> Result<Ret, ProgramError> {
    let prog = Pubkey::new_unique();
    let lp = Pubkey::new_from_array([7; 32]);
    let key = Pubkey::new_unique();
    let mut data_buf = ctx_bytes(c);
    let mut lam = 1u64;
    let mut lpl = 0u64;
    let lp_ai = AccountInfo::new(&lp, true, false, &mut lpl, &mut [], &prog, false, 0);
    let ctx_ai = AccountInfo::new(&key, false, true, &mut lam, &mut data_buf, &prog, false, 0);
    vamm::process_call_with_clock(&lp_ai, &ctx_ai, data, clock)?;
    drop(ctx_ai);
    let d = &data_buf;
    Ok(Ret {
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

fn run_batch(c: &MatcherCtx, data: &[u8]) -> Result<i128, ProgramError> {
    let prog = Pubkey::new_unique();
    let lp = Pubkey::new_from_array([7; 32]);
    let key = Pubkey::new_unique();
    let mut data_buf = ctx_bytes(c);
    let mut lam = 1u64;
    let mut lpl = 0u64;
    let lp_ai = AccountInfo::new(&lp, true, false, &mut lpl, &mut [], &prog, false, 0);
    let ctx_ai = AccountInfo::new(&key, false, true, &mut lam, &mut data_buf, &prog, false, 0);
    vamm::process_batch_call_with_clock(&lp_ai, &ctx_ai, data, clock)?;
    drop(ctx_ai);
    Ok(MatcherCtx::read_from(&data_buf[CTX_VAMM_OFFSET..])
        .unwrap()
        .inventory_base)
}

fn batch_bytes(legs: &[(u16, i128)], exts: &[Vec<u8>]) -> Vec<u8> {
    let mut d = vec![3u8, legs.len() as u8];
    d.extend_from_slice(&1u64.to_le_bytes());
    d.extend_from_slice(&LP_ID.to_le_bytes());
    for (asset, size) in legs {
        d.extend_from_slice(&asset.to_le_bytes());
        d.extend_from_slice(&PX.to_le_bytes());
        d.extend_from_slice(&size.to_le_bytes());
    }
    for e in exts {
        d.extend_from_slice(e);
    }
    d
}

fn v3_block(lp_pos: i128, cap: u128, liq: u128) -> Vec<u8> {
    CallExt {
        lp_position_q: Some(lp_pos),
        ..CallExt::default()
    }
    .encode_v3(&ExtCapsV3 {
        inventory_cap_q: cap,
        liquidity_notional_e6: liq,
    })
    .to_vec()
}

fn v2_block(lp_pos: i128) -> Vec<u8> {
    CallExt {
        lp_position_q: Some(lp_pos),
        ..CallExt::default()
    }
    .encode_v2()
    .to_vec()
}

// ── wire ─────────────────────────────────────────────────────────────────────────────

#[test]
fn v3_block_roundtrips_and_is_strict() {
    let e = CallExt {
        headroom_q: Some(9),
        mark_slot: Some(77),
        accepts_fee_request: true,
        taker_reducing: true,
        exec_band_bps: Some(500),
        lp_position_q: Some(-123_456_789),
    };
    let caps = ExtCapsV3 {
        inventory_cap_q: 5_000,
        liquidity_notional_e6: 7_000_000,
    };
    let b = e.encode_v3(&caps);
    assert_eq!(b.len(), v2::CALL_EXT_V3_LEN);
    assert_eq!(b[0], v2::CALL_EXT_VERSION_V3);
    // the first 40 bytes are the v2 block with only the version byte changed
    let mut v2b = e.encode_v2();
    v2b[0] = v2::CALL_EXT_VERSION_V3;
    assert_eq!(&b[..40], &v2b[..]);
    assert_eq!(CallExt::parse_v3(&b).unwrap(), (e, caps));
    assert_eq!(CallExt::parse_any_caps(&b).unwrap(), (e, Some(caps)));
    // v1/v2 through the caps parser carry no caps
    assert_eq!(CallExt::parse_any_caps(&e.encode_v2()).unwrap(), (e, None));
    // the legacy parser does not accept a 72-byte block (no silent cap drop)
    assert!(CallExt::parse_any(&b).is_err());
    // version / length mismatches fail closed
    let mut bad = b;
    bad[0] = v2::CALL_EXT_VERSION_V2;
    assert!(CallExt::parse_v3(&bad).is_err());
    assert!(CallExt::parse_any_caps(&bad).is_err());
    assert!(CallExt::parse_v3(&b[..71]).is_err());
    // an inventory cap above i128::MAX fails closed
    let mut over = b;
    over[40..56].copy_from_slice(&(i128::MAX as u128 + 1).to_le_bytes());
    assert!(CallExt::parse_v3(&over).is_err());
    // v1 rules still apply inside v3 (unknown flag)
    let mut flag = b;
    flag[1] |= 1 << 7;
    assert!(CallExt::parse_v3(&flag).is_err());
    // i128::MIN position refused
    let mut minpos = b;
    minpos[24..40].copy_from_slice(&i128::MIN.to_le_bytes());
    assert!(CallExt::parse_v3(&minpos).is_err());
}

#[test]
fn v3_call_length_is_exact() {
    let c = ctx(1, 0, 0);
    let good = call_v3(10, 0, 1_000, 1_000_000_000_000);
    assert!(run(&c, &good).is_ok());
    // byte 43 == 3 with the v2 length (83) or a trailing byte: refused
    let mut short = good.clone();
    short.truncate(MATCHER_CALL_V2_LEN);
    assert_eq!(run(&c, &short), Err(ProgramError::InvalidInstructionData));
    let mut long = good;
    long.push(0);
    assert_eq!(run(&c, &long), Err(ProgramError::InvalidInstructionData));
}

#[test]
fn batch_never_mixes_widths() {
    let c = ctx(1, 0, 0);
    let ok = batch_bytes(
        &[(0, 5), (1, 5)],
        &[v3_block(0, 100, 0), v3_block(0, 100, 0)],
    );
    assert!(run_batch(&c, &ok).is_ok());
    let mixed = batch_bytes(&[(0, 5), (1, 5)], &[v3_block(0, 100, 0), v2_block(0)]);
    assert_eq!(
        run_batch(&c, &mixed),
        Err(ProgramError::InvalidInstructionData)
    );
}

// ── parity v1 / v2 / v3 (caps that do not bind) ─────────────────────────────────────

#[test]
fn parity_v1_v2_v3_when_caps_do_not_bind() {
    for &(kind, cap) in &[(0u8, 0u128), (1, 0), (1, 1_000_000), (0, 1_000_000)] {
        for &(inv, size) in &[(0i128, 300i128), (500, -200), (-400, 250), (0, -1_000)] {
            let c = ctx(kind, inv, cap);
            let r1 = run(&c, &call_v1(size)).unwrap();
            let r2 = run(&c, &call_v2(size, inv)).unwrap();
            // neutral caps: >= any context cap, depth >= the context depth
            let r3 = run(&c, &call_v3(size, inv, i128::MAX as u128, u128::MAX)).unwrap();
            assert_eq!(
                r1, r2,
                "kind {kind} cap {cap} inv {inv} size {size}: v1 vs v2"
            );
            assert_eq!(
                r2, r3,
                "kind {kind} cap {cap} inv {inv} size {size}: v2 vs v3"
            );
        }
    }
    // kind 2 (needs the v2 block + clock)
    for &(inv, size) in &[(0i128, 300i128), (500, -200), (-400, 250)] {
        let c = ctx_kind2(inv, 1_000_000);
        let r2 = run(&c, &call_v2(size, inv)).unwrap();
        let r3 = run(&c, &call_v3(size, inv, i128::MAX as u128, u128::MAX)).unwrap();
        assert_eq!(r2, r3, "kind 2 inv {inv} size {size}: v2 vs v3");
    }
}

// ── min(ctx, ext) ───────────────────────────────────────────────────────────────────

#[test]
fn v3_inventory_cap_is_min_of_ctx_and_ext() {
    // LP flat, taker buys 1,000 => LP would go -1,000.
    // ext cap 300 < ctx cap 1,000_000: ext binds.
    let c = ctx(1, 0, 1_000_000);
    let r = run(&c, &call_v3(1_000, 0, 300, u128::MAX)).unwrap();
    assert_eq!(r.exec_size, 300);
    // ctx cap 200 < ext cap 300: ctx binds (never looser than the context).
    let c = ctx(1, 0, 200);
    let r = run(&c, &call_v3(1_000, 0, 300, u128::MAX)).unwrap();
    assert_eq!(r.exec_size, 200);
    // ctx cap 0 (unlimited, legacy): the ext cap binds.
    let c = ctx(1, 0, 0);
    let r = run(&c, &call_v3(1_000, 0, 300, u128::MAX)).unwrap();
    assert_eq!(r.exec_size, 300);
    // negative control: the same calls on v2 are unclipped / ctx-clipped only.
    assert_eq!(
        run(&ctx(1, 0, 0), &call_v2(1_000, 0)).unwrap().exec_size,
        1_000
    );
    assert_eq!(
        run(&ctx(1, 0, 1_000_000), &call_v2(1_000, 0))
            .unwrap()
            .exec_size,
        1_000
    );
    // kind 2: the ext cap binds too
    let r = run(&ctx_kind2(0, 1_000_000), &call_v3(1_000, 0, 300, u128::MAX)).unwrap();
    assert!(
        r.exec_size > 0 && r.exec_size <= 300,
        "kind 2 clipped to the ext cap: {}",
        r.exec_size
    );
}

#[test]
fn v3_zero_cap_is_closed_not_unlimited() {
    // LP short 500. A buy grows the LP's |inventory| => closed => zero fill.
    let c = ctx(1, -500, 0);
    let r = run(&c, &call_v3(100, -500, 0, 0)).unwrap();
    assert_eq!(r.exec_size, 0, "closed: no LP growth");
    // A sell reduces the LP => allowed, but only up to flat (never through it).
    let r = run(&c, &call_v3(-300, -500, 0, 0)).unwrap();
    assert_eq!(r.exec_size, -300);
    let r = run(&c, &call_v3(-900, -500, 0, 0)).unwrap();
    assert_eq!(r.exec_size, -500, "reduce to flat, never flip");
    // Flat LP: closed both ways.
    let flat = ctx(1, 0, 0);
    assert_eq!(run(&flat, &call_v3(100, 0, 0, 0)).unwrap().exec_size, 0);
    assert_eq!(run(&flat, &call_v3(-100, 0, 0, 0)).unwrap().exec_size, 0);
    // negative control: in the legacy context, 0 means UNLIMITED.
    assert_eq!(run(&c, &call_v2(100, -500)).unwrap().exec_size, 100);
    // kind 2 closed too
    let k2 = ctx_kind2(-500, 1_000_000);
    assert_eq!(run(&k2, &call_v3(100, -500, 0, 0)).unwrap().exec_size, 0);
    assert_eq!(
        run(&k2, &call_v3(-100, -500, 0, 0)).unwrap().exec_size,
        -100
    );
}

#[test]
fn v3_less_capital_moves_the_quote_more() {
    // kind 1, impact 100 bps per 100% of depth. The same 1,000-unit order on $1,000 vs $50,000
    // of capital-derived depth (the ext liquidity; ctx depth is the ceiling).
    let mut c = ctx(1, 0, 0);
    c.liquidity_notional_e6 = 1_000_000_000_000;
    c.max_total_bps = 9_000;
    let thin = run(
        &c,
        &call_v3(10_000_000, 0, i128::MAX as u128, 1_000_000_000),
    )
    .unwrap();
    let deep = run(
        &c,
        &call_v3(10_000_000, 0, i128::MAX as u128, 50_000_000_000),
    )
    .unwrap();
    assert!(
        thin.exec_price_e6 > deep.exec_price_e6,
        "thin {} deep {}",
        thin.exec_price_e6,
        deep.exec_price_e6
    );
    // never looser than the ctx: an ext depth ABOVE the ctx keeps the ctx depth
    let ceiling = run(&c, &call_v3(10_000_000, 0, i128::MAX as u128, u128::MAX)).unwrap();
    let ctx_only = run(&c, &call_v2(10_000_000, 0)).unwrap();
    assert_eq!(ceiling, ctx_only);
    // ext depth 0 == no depth information: ctx depth kept (an exit is not priced at the clamp)
    let zero = run(&c, &call_v3(10_000_000, 0, i128::MAX as u128, 0)).unwrap();
    assert_eq!(zero, ctx_only);
}

#[test]
fn v3_batch_caps_apply_per_leg() {
    // two legs on asset 0 (same direction): the cap is the LP inventory bound, so together
    // they cannot take the LP past 300.
    let c = ctx(1, 0, 0);
    let d = batch_bytes(
        &[(0, 200), (0, 200)],
        &[v3_block(0, 300, 0), v3_block(0, 300, 0)],
    );
    assert_eq!(run_batch(&c, &d), Ok(-300));
    // negative control: v2 legs are unbounded on an unlimited context
    let d2 = batch_bytes(&[(0, 200), (0, 200)], &[v2_block(0), v2_block(0)]);
    assert_eq!(run_batch(&c, &d2), Ok(-400));
}

// ── kind-1 skew units (GAP B.2.3) ───────────────────────────────────────────────────

/// The legacy formula: bps per raw Q / 10_000, capped at 5000.
fn legacy_skew(inv_abs: u128, mult: u128) -> u128 {
    (inv_abs.saturating_mul(mult) / 10_000).min(5_000)
}

#[test]
fn kind1_skew_is_bps_per_100pct_of_cap() {
    // A memecoin-sized book: cap 1e13 Q (10M tokens), LP long 1e12 Q (1M tokens, 10% of cap),
    // skew 100 bps per 100% of the cap. A user SELL worsens the LP's long.
    let cap: u128 = 10_000_000_000_000;
    let inv: i128 = 1_000_000_000_000;
    let mut c = ctx(1, inv, cap);
    c.max_total_bps = 9_000;
    c.impact_k_bps = 0;
    c.skew_spread_mult_bps = 100;
    let skewed = run(&c, &call_v3(-1, inv, cap, u128::MAX)).unwrap();
    c.skew_spread_mult_bps = 0;
    let plain = run(&c, &call_v3(-1, inv, cap, u128::MAX)).unwrap();
    // bid side: price = floor(oracle * (1e4 - total) / 1e4); 10 bps more spread at $100 = 0.1
    // dollars = 100,000 e6 lower.
    let diff = plain.exec_price_e6 - skewed.exec_price_e6;
    assert_eq!(diff, 100_000, "10% of cap * 100 bps = 10 bps");
    // the legacy formula saturates at once on the same book (the bug)
    assert_eq!(legacy_skew(inv.unsigned_abs(), 100), 5_000);
    // at 50% of the cap the extra is half the multiplier (a worsening fill AT the cap is
    // clipped to zero by the inventory limit, so the slope is measured below it)
    let half = (cap / 2) as i128;
    let mut h = ctx(1, half, cap);
    h.max_total_bps = 9_000;
    h.impact_k_bps = 0;
    h.skew_spread_mult_bps = 100;
    let f = run(&h, &call_v3(-1, half, cap, u128::MAX)).unwrap();
    h.skew_spread_mult_bps = 0;
    let fp = run(&h, &call_v3(-1, half, cap, u128::MAX)).unwrap();
    assert_eq!(f.exec_size, -1);
    assert_eq!(
        fp.exec_price_e6 - f.exec_price_e6,
        500_000,
        "50% of cap = 50 bps"
    );
}

#[test]
fn kind1_skew_reference_is_the_v3_effective_cap() {
    // ctx cap is the non-binding growth pin (1e14); the ext cap N_cap = 1e13 is the reference.
    let inv: i128 = 1_000_000_000_000;
    let mut c = ctx(1, inv, 100_000_000_000_000);
    c.max_total_bps = 9_000;
    c.impact_k_bps = 0;
    c.skew_spread_mult_bps = 100;
    let with_cap = run(&c, &call_v3(-1, inv, 10_000_000_000_000, u128::MAX)).unwrap();
    let wider = run(&c, &call_v3(-1, inv, 50_000_000_000_000, u128::MAX)).unwrap();
    // 10% of a 1e13 ext cap => 10 bps; 2% of a 5e13 ext cap => 2 bps
    assert_eq!(wider.exec_price_e6 - with_cap.exec_price_e6, 80_000);
}

#[test]
fn kind1_skew_without_cap_reference_is_legacy() {
    // unlimited (0) and the i128::MAX sentinel keep the legacy units byte for byte
    for cap in [0u128, i128::MAX as u128] {
        let mut c = ctx(1, 1_000, cap);
        c.max_total_bps = 9_000;
        c.impact_k_bps = 0;
        c.skew_spread_mult_bps = 100;
        let s = run(&c, &call_v2(-1, 1_000)).unwrap();
        c.skew_spread_mult_bps = 0;
        let p = run(&c, &call_v2(-1, 1_000)).unwrap();
        // legacy: 1,000 * 100 / 10,000 = 10 bps
        assert_eq!(p.exec_price_e6 - s.exec_price_e6, 100_000, "cap {cap}");
        assert_eq!(legacy_skew(1_000, 100), 10);
    }
}

#[test]
fn v3_effective_helpers() {
    assert_eq!(v2::v3_effective_max_inventory(0, 5), Some(5));
    assert_eq!(v2::v3_effective_max_inventory(3, 5), Some(3));
    assert_eq!(v2::v3_effective_max_inventory(7, 5), Some(5));
    assert_eq!(v2::v3_effective_max_inventory(7, 0), None);
    assert_eq!(v2::v3_effective_max_inventory(0, 0), None);
    assert_eq!(v2::v3_effective_liquidity(10, 0), 10);
    assert_eq!(v2::v3_effective_liquidity(10, 4), 4);
    assert_eq!(v2::v3_effective_liquidity(10, 40), 10);
    // closed room: only an LP-reducing fill, up to flat
    assert_eq!(
        v2::v3_closed_room(500, true),
        500,
        "LP long, user buys: LP sells down"
    );
    assert_eq!(v2::v3_closed_room(500, false), 0);
    assert_eq!(v2::v3_closed_room(-500, false), 500);
    assert_eq!(v2::v3_closed_room(-500, true), 0);
    assert_eq!(v2::v3_closed_room(0, true), 0);
    assert_eq!(v2::v3_closed_room(i128::MIN + 1, false), i128::MAX as u128);
}

// ── security review 2026-10-04: L-1 opt-in units, L-5 neutral caps, M-1 close exemption ──

/// L-1: the kind-1 unit fix is OPT-IN. A legacy / v1 / v2 call on a finite-cap kind-1 context
/// keeps the deployed formula byte for byte (the live HqLMqhtM... context is unchanged).
#[test]
fn l1_kind1_units_only_under_an_active_v3_cap() {
    let cap: u128 = 10_000_000_000_000;
    let inv: i128 = 1_000_000_000_000;
    let mut c = ctx(1, inv, cap);
    c.max_total_bps = 9_000;
    c.impact_k_bps = 0;
    c.skew_spread_mult_bps = 100;
    let v1 = run(&c, &call_v1(-1)).unwrap();
    let v2 = run(&c, &call_v2(-1, inv)).unwrap();
    let v3 = run(&c, &call_v3(-1, inv, cap, u128::MAX)).unwrap();
    c.skew_spread_mult_bps = 0;
    let plain = run(&c, &call_v2(-1, inv)).unwrap();
    // legacy: 1e12 * 100 / 1e4 -> saturates at 5000 bps
    assert_eq!(
        plain.exec_price_e6 - v2.exec_price_e6,
        50_000_000,
        "v2: legacy units"
    );
    assert_eq!(
        v1.exec_price_e6, v2.exec_price_e6,
        "v1 == v2 (same inventory)"
    );
    // v3 with an active cap: 10% of cap -> 10 bps
    assert_eq!(
        plain.exec_price_e6 - v3.exec_price_e6,
        100_000,
        "v3: new units"
    );
}

/// L-5: the wrapper's neutral pair for non-growth legs of a mixed batch, (1e14, u128::MAX),
/// is TRULY neutral -- also for a kind-1 context with an unlimited cap and skew on.
#[test]
fn l5_neutral_v3_caps_are_neutral_for_unlimited_kind1() {
    let neutral_cap: u128 = 100_000_000_000_000; // MAX_POSITION_ABS_Q
                                                 // large inventories so the legacy skew is visible (it saturates at 5000 bps / max_total)
    for (inv, size) in [
        (5_000_000_000i128, -300i128),
        (-5_000_000_000, 300),
        (1_000_000, -300),
        (0, 300),
    ] {
        let mut c = ctx(1, inv, 0);
        c.skew_spread_mult_bps = 7;
        c.max_total_bps = 9_000;
        let v2 = run(&c, &call_v2(size, inv)).unwrap();
        let v3 = run(&c, &call_v3(size, inv, neutral_cap, u128::MAX)).unwrap();
        assert_eq!(
            v2, v3,
            "inv {inv}: the neutral pair must price exactly like v2"
        );
        let v3_above = run(&c, &call_v3(size, inv, i128::MAX as u128, u128::MAX)).unwrap();
        assert_eq!(v2, v3_above);
    }
}

fn call_v3_reducing(size: i128, lp_pos: i128, cap: u128, liq: u128) -> Vec<u8> {
    let mut d = vec![0u8; MATCHER_CALL_V3_LEN];
    head(&mut d, size);
    let e = CallExt {
        lp_position_q: Some(lp_pos),
        taker_reducing: true,
        ..base_ext()
    };
    d[43..115].copy_from_slice(&e.encode_v3(&ExtCapsV3 {
        inventory_cap_q: cap,
        liquidity_notional_e6: liq,
    }));
    d
}

/// M-1: a wrapper-verified taker REDUCTION is never clipped for LP capacity: not by the v3
/// cap, not by closed mode (cap 0), not by the kind-2 size budget. Controls: the identical
/// call without TAKER_REDUCING is clipped.
#[test]
fn m1_taker_reducing_is_never_clipped_for_lp_capacity() {
    // LP short 1,000 at a 1,000 cap; a thin-side close (user buys 100) grows |LP| to 1,100.
    for kind in [0u8, 1] {
        let c = ctx(kind, -1_000, 0);
        let exempt = run(&c, &call_v3_reducing(100, -1_000, 1_000, u128::MAX)).unwrap();
        assert_eq!(
            exempt.exec_size, 100,
            "kind {kind}: close filled past the cap"
        );
        let control = run(&c, &call_v3(100, -1_000, 1_000, u128::MAX)).unwrap();
        assert_eq!(
            control.exec_size, 0,
            "kind {kind}: without the flag the cap clips"
        );
        // closed mode (cap 0: h-lock / C_m = 0)
        let closed = run(&c, &call_v3_reducing(100, -1_000, 0, 0)).unwrap();
        assert_eq!(
            closed.exec_size, 100,
            "kind {kind}: closed mode never traps a close"
        );
        let closed_ctl = run(&c, &call_v3(100, -1_000, 0, 0)).unwrap();
        assert_eq!(closed_ctl.exec_size, 0);
    }
    // kind 2: a tiny depth makes the constant-product impact infeasible for this size
    let k2 = ctx_kind2(-1_000, 1_000_000);
    let exempt = run(&k2, &call_v3_reducing(500, -1_000, 1_000, 10)).unwrap();
    assert_eq!(
        exempt.exec_size, 500,
        "kind 2: the size budget never clips a close"
    );
    // priced at the max-total clamp (400 bps over the oracle for a buy)
    assert!(
        exempt.exec_price_e6 >= PX + PX / 10_000 * 400 - 1,
        "priced at the clamp: {}",
        exempt.exec_price_e6
    );
    let ctl = run(&k2, &call_v3(500, -1_000, 1_000, 10)).unwrap();
    assert!(
        ctl.exec_size < 500,
        "kind 2 control: clipped ({})",
        ctl.exec_size
    );
    // the flag on a v2 call (no v3 caps) changes nothing (legacy semantics unchanged)
    let legacy = ctx(1, -1_000, 1_000);
    let mut d = vec![0u8; MATCHER_CALL_V2_LEN];
    head(&mut d, 100);
    let e = CallExt {
        lp_position_q: Some(-1_000),
        taker_reducing: true,
        ..base_ext()
    };
    d[43..83].copy_from_slice(&e.encode_v2());
    assert_eq!(
        run(&legacy, &d).unwrap().exec_size,
        0,
        "v2: ctx cap still binds"
    );
}

/// Kani-extraction pins (security re-verification Q5): `v2::v3_apply_caps` (exempt => no clip),
/// `v2::v3_close_exempt_fill` and `vamm::v3_effective_ctx` (neutral caps == v2 context).
#[test]
fn v3_extractions_exempt_means_no_clip_and_neutral_is_v2() {
    // finite cap: clipped unless exempt
    let c = v2::v3_apply_caps(1_000, 500, -900, 950, false, false);
    assert_eq!(
        (c.max_inventory_abs, c.max_fill_abs, c.skew_ref_cap),
        (950, 500, Some(950))
    );
    let e = v2::v3_apply_caps(1_000, 500, -900, 950, false, true);
    assert_eq!(
        (e.max_inventory_abs, e.max_fill_abs, e.skew_ref_cap),
        (1_000, 500, Some(950))
    );
    // closed: a growing request gets room 0 unless exempt
    let c = v2::v3_apply_caps(1_000, 500, -900, 0, true, false);
    assert_eq!((c.max_fill_abs, c.skew_ref_cap), (0, None));
    let e = v2::v3_apply_caps(1_000, 500, -900, 0, true, true);
    assert_eq!((e.max_inventory_abs, e.max_fill_abs), (1_000, 500));
    // exhaustive "exempt => limits unchanged" on a small domain
    for inv in -3i128..=3 {
        for cap in 0u128..=4 {
            for (mi, mf) in [(0u128, 0u128), (2, 3), (5, 1)] {
                for buy in [false, true] {
                    let x = v2::v3_apply_caps(mi, mf, inv, cap, buy, true);
                    assert_eq!((x.max_inventory_abs, x.max_fill_abs), (mi, mf));
                }
            }
        }
    }
    // kind-2 exempt fill: full size at the clamp price; otherwise the quote stands
    assert_eq!(v2::v3_close_exempt_fill(true, 10, 101, 40, 109), (40, 109));
    assert_eq!(v2::v3_close_exempt_fill(false, 10, 101, 40, 109), (10, 101));
    assert_eq!(v2::v3_close_exempt_fill(true, 40, 101, 40, 109), (40, 101));
    // R3: neutral caps (>= 1e14, liq u128::MAX) leave the v2 effective context unchanged
    let base = ctx_kind2(-500, 0);
    let mut ext = base_ext();
    ext.headroom_q = Some(777);
    let v2e = vamm::v3_effective_ctx(&base, &ext, None, true, 0);
    let neutral = ExtCapsV3 {
        inventory_cap_q: u128::MAX,
        liquidity_notional_e6: u128::MAX,
    };
    let v3e = vamm::v3_effective_ctx(&base, &ext, Some(neutral), true, 0);
    assert!(!v3e.cap_active && !v3e.close_exempt && v3e.skew_ref_cap.is_none());
    assert_eq!(
        (
            v3e.ctx.max_inventory_abs,
            v3e.ctx.max_fill_abs,
            v3e.ctx.liquidity_notional_e6,
            v3e.ctx.max_total_bps
        ),
        (
            v2e.ctx.max_inventory_abs,
            v2e.ctx.max_fill_abs,
            v2e.ctx.liquidity_notional_e6,
            v2e.ctx.max_total_bps
        )
    );
    // an exempt leg under an active closed cap keeps the v2 limits too
    ext.taker_reducing = true;
    let closed = ExtCapsV3 {
        inventory_cap_q: 0,
        liquidity_notional_e6: 0,
    };
    let x = vamm::v3_effective_ctx(&base, &ext, Some(closed), true, 0);
    assert!(x.cap_active && x.close_exempt);
    assert_eq!(
        (x.ctx.max_inventory_abs, x.ctx.max_fill_abs),
        (v2e.ctx.max_inventory_abs, v2e.ctx.max_fill_abs)
    );
}
