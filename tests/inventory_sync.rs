//! Matcher-inventory-sync (2026-10-03): a version-2 call extension carries the LP's REAL
//! signed engine position, and the matcher prices/caps against it instead of its stored
//! `inventory_base` counter.
//!
//! Why: the counter only moves on matcher fills. Liquidations, ADL scaling, side resets,
//! RebalanceReduce, force-close and no-CPI trades move the LP's engine leg without the matcher,
//! so the counter drifts. On devnet (wrapper ETDLAdi / matcher EDKKgRaV, 2026-10-03) 11 of 44
//! bound contexts had drifted: phantom caps that block closes (e.g. counter -9.724e9 = -cap
//! while the LP was really -2.348e9) and, the other way, fills allowed past the configured cap
//! (upstream percolator-prog#406). Cross-asset netting of the single scalar is
//! percolator-match#8.
//!
//! Every mechanism test pairs with a NEGATIVE CONTROL: the identical call with a v1 (or v0)
//! extension, i.e. no position, reproduces the stale-counter behaviour.

use percolator_match::v2::{self, CallExt};
use percolator_match::vamm::{self, MatcherCtx, MATCHER_MAGIC, MATCHER_VERSION};
use percolator_match::{
    MatcherReturn, CTX_VAMM_OFFSET, FLAG_PARTIAL_OK, MATCHER_CALL_V2_LEN, MATCHER_CONTEXT_LEN,
};
use solana_program::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};

const LP_ID: u64 = 42;
const PX: u64 = 100_000_000;
const CAP: u128 = 1_000;

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

fn no_clock() -> Result<u64, ProgramError> {
    panic!("a block-less context must not read the clock")
}

fn ctx_bytes(c: &MatcherCtx) -> Vec<u8> {
    let mut d = vec![0u8; MATCHER_CONTEXT_LEN];
    c.write_to(&mut d[CTX_VAMM_OFFSET..]).unwrap();
    d
}

fn head(d: &mut [u8], price: u64, size: i128) {
    d[1..9].copy_from_slice(&1u64.to_le_bytes());
    d[11..19].copy_from_slice(&LP_ID.to_le_bytes());
    d[19..27].copy_from_slice(&price.to_le_bytes());
    d[27..43].copy_from_slice(&size.to_le_bytes());
}

/// Tag-0 call with a v1/v0 block (67 bytes) -- the stale-counter path.
fn call_v1(size: i128, ext: &CallExt) -> Vec<u8> {
    let mut d = vec![0u8; 67];
    head(&mut d, PX, size);
    d[43..67].copy_from_slice(&ext.encode());
    d
}

/// Tag-0 call with a v2 block (83 bytes) carrying `lp_pos`.
fn call_v2(size: i128, lp_pos: i128, base: &CallExt) -> Vec<u8> {
    let mut d = vec![0u8; MATCHER_CALL_V2_LEN];
    head(&mut d, PX, size);
    let e = CallExt {
        lp_position_q: Some(lp_pos),
        ..*base
    };
    d[43..83].copy_from_slice(&e.encode_v2());
    d
}

struct Out {
    ret: MatcherReturn,
    inv_after: i128,
}

fn run(c: &MatcherCtx, data: &[u8]) -> Result<Out, ProgramError> {
    let prog = Pubkey::new_unique();
    let lp = Pubkey::new_from_array([7; 32]);
    let key = Pubkey::new_unique();
    let mut data_buf = ctx_bytes(c);
    let mut lam = 1u64;
    let mut lpl = 0u64;
    let lp_ai = AccountInfo::new(&lp, true, false, &mut lpl, &mut [], &prog, false, 0);
    let ctx_ai = AccountInfo::new(&key, false, true, &mut lam, &mut data_buf, &prog, false, 0);
    vamm::process_call_with_clock(&lp_ai, &ctx_ai, data, no_clock)?;
    drop(ctx_ai);
    let d = &data_buf;
    Ok(Out {
        ret: MatcherReturn {
            abi_version: u32::from_le_bytes(d[0..4].try_into().unwrap()),
            flags: u32::from_le_bytes(d[4..8].try_into().unwrap()),
            exec_price_e6: u64::from_le_bytes(d[8..16].try_into().unwrap()),
            exec_size: i128::from_le_bytes(d[16..32].try_into().unwrap()),
            req_id: u64::from_le_bytes(d[32..40].try_into().unwrap()),
            lp_account_id: u64::from_le_bytes(d[40..48].try_into().unwrap()),
            oracle_price_e6: u64::from_le_bytes(d[48..56].try_into().unwrap()),
            asset_index: u64::from_le_bytes(d[56..64].try_into().unwrap()),
        },
        inv_after: MatcherCtx::read_from(&d[CTX_VAMM_OFFSET..])
            .unwrap()
            .inventory_base,
    })
}

fn run_batch(c: &MatcherCtx, data: &[u8]) -> Result<((), i128), ProgramError> {
    let prog = Pubkey::new_unique();
    let lp = Pubkey::new_from_array([7; 32]);
    let key = Pubkey::new_unique();
    let mut data_buf = ctx_bytes(c);
    let mut lam = 1u64;
    let mut lpl = 0u64;
    let lp_ai = AccountInfo::new(&lp, true, false, &mut lpl, &mut [], &prog, false, 0);
    let ctx_ai = AccountInfo::new(&key, false, true, &mut lam, &mut data_buf, &prog, false, 0);
    // Per-leg returns go through set_return_data (a no-op natively); the tests assert on the
    // inventory the context ends with, which is determined by every leg's fill.
    vamm::process_batch_call_with_clock(&lp_ai, &ctx_ai, data, no_clock)?;
    drop(ctx_ai);
    let inv = MatcherCtx::read_from(&data_buf[CTX_VAMM_OFFSET..])
        .unwrap()
        .inventory_base;
    Ok(((), inv))
}

fn batch_bytes(legs: &[(u16, i128)], exts: Option<&[Vec<u8>]>) -> Vec<u8> {
    let mut d = vec![3u8, legs.len() as u8];
    d.extend_from_slice(&1u64.to_le_bytes());
    d.extend_from_slice(&LP_ID.to_le_bytes());
    for (asset, size) in legs {
        d.extend_from_slice(&asset.to_le_bytes());
        d.extend_from_slice(&PX.to_le_bytes());
        d.extend_from_slice(&size.to_le_bytes());
    }
    if let Some(exts) = exts {
        for e in exts {
            d.extend_from_slice(e);
        }
    }
    d
}

fn v2_block(lp_pos: i128) -> Vec<u8> {
    CallExt {
        lp_position_q: Some(lp_pos),
        ..CallExt::default()
    }
    .encode_v2()
    .to_vec()
}

fn key(r: &MatcherReturn) -> (u32, u32, u64, i128, u64, u64, u64, u64) {
    (
        r.abi_version,
        r.flags,
        r.exec_price_e6,
        r.exec_size,
        r.req_id,
        r.lp_account_id,
        r.oracle_price_e6,
        r.asset_index,
    )
}

// ── wire ─────────────────────────────────────────────────────────────────────────────

#[test]
fn v2_block_roundtrips_and_is_strict() {
    let e = CallExt {
        headroom_q: Some(9),
        mark_slot: Some(77),
        accepts_fee_request: true,
        taker_reducing: true,
        exec_band_bps: Some(500),
        lp_position_q: Some(-123_456_789),
    };
    let b = e.encode_v2();
    assert_eq!(b[0], v2::CALL_EXT_VERSION_V2);
    assert_eq!(CallExt::parse_v2(&b).unwrap(), e);
    assert_eq!(CallExt::parse_any(&b).unwrap(), e);
    // a v2 block with no v1 field is still a v2 block (not legacy)
    let bare = CallExt {
        lp_position_q: Some(0),
        ..CallExt::default()
    };
    assert!(!bare.is_legacy());
    assert_eq!(CallExt::parse_v2(&bare.encode_v2()).unwrap(), bare);
    // the 24-byte parser refuses version 2; the v2 parser refuses version 1
    let mut v2_as_24 = [0u8; 24];
    v2_as_24.copy_from_slice(&b[..24]);
    assert!(
        CallExt::parse(&v2_as_24).is_err(),
        "v1 parser must reject version 2"
    );
    let mut wrong_ver = b;
    wrong_ver[0] = 1;
    assert!(CallExt::parse_v2(&wrong_ver).is_err());
    // v1 rules still apply inside v2: unknown flag, reserved bytes, field without flag
    let mut bad = b;
    bad[1] |= 1 << 5;
    assert!(CallExt::parse_v2(&bad).is_err(), "unknown flag");
    let mut bad = b;
    bad[21] = 1;
    assert!(CallExt::parse_v2(&bad).is_err(), "reserved 20..24");
    let mut bad = bare.encode_v2();
    bad[12] = 1; // headroom without HEADROOM flag
    assert!(CallExt::parse_v2(&bad).is_err(), "field without flag");
    // i128::MIN refused
    let mut bad = bare.encode_v2();
    bad[24..40].copy_from_slice(&i128::MIN.to_le_bytes());
    assert!(CallExt::parse_v2(&bad).is_err(), "i128::MIN position");
}

#[test]
fn tag0_v2_call_must_be_exactly_83_bytes() {
    let c = ctx(0, 0, 0);
    let mut d = call_v2(5, 0, &CallExt::default());
    assert!(run(&c, &d).is_ok(), "control: 83-byte v2 call fills");
    d.push(0);
    assert!(run(&c, &d).is_err(), "84 bytes with version 2");
    let short = call_v2(5, 0, &CallExt::default())[..67].to_vec();
    assert!(run(&c, &short).is_err(), "67 bytes with version 2");
}

// ── single call (tag 0) ──────────────────────────────────────────────────────────────

/// 4EGvEGdL shape: counter pinned at -cap, LP really much less short. A short taker closing
/// (taker BUYS => LP sells => inventory decreases) is blocked by the stale counter only.
#[test]
fn stale_counter_at_minus_cap_blocks_close_v2_position_lets_it_fill() {
    for kind in [0u8, 1] {
        let c = ctx(kind, -(CAP as i128), CAP);
        // negative control: no position => the counter says LP is at -cap => zero fill
        let stale = run(&c, &call_v1(400, &CallExt::default())).unwrap();
        assert_eq!(
            stale.ret.exec_size, 0,
            "kind {kind}: stale counter zero-fills"
        );
        assert_ne!(stale.ret.flags & FLAG_PARTIAL_OK, 0);
        // fix: the real LP position is -241 (ADL scaled it) => 400 fits (-641 within cap)
        let real = run(&c, &call_v2(400, -241, &CallExt::default())).unwrap();
        assert_eq!(
            real.ret.exec_size, 400,
            "kind {kind}: real position fills fully"
        );
        assert_eq!(
            real.inv_after, -641,
            "kind {kind}: counter re-synchronised to real - fill"
        );
    }
}

/// Gprscv7A shape: counter at +cap, LP flat. Nobody can open a short (taker SELL) under the
/// counter; with the real (flat) position a cap-sized short fills.
#[test]
fn stale_counter_at_plus_cap_blocks_opens_v2_flat_lp_fills_up_to_cap() {
    let c = ctx(0, CAP as i128, CAP);
    let stale = run(&c, &call_v1(-(CAP as i128), &CallExt::default())).unwrap();
    assert_eq!(
        stale.ret.exec_size, 0,
        "control: counter at +cap blocks every sell"
    );
    let real = run(&c, &call_v2(-(CAP as i128), 0, &CallExt::default())).unwrap();
    assert_eq!(real.ret.exec_size, -(CAP as i128));
    assert_eq!(real.inv_after, CAP as i128);
}

/// percolator-prog#406 direction: the counter UNDER-states the LP, so the matcher lets the LP
/// past its configured cap. With the real position the fill is clipped at the cap.
#[test]
fn stale_counter_bypass_past_cap_is_clipped_by_real_position() {
    // counter -cap (stale), LP really flat; a taker sells 2*cap (LP buys 2*cap)
    let c = ctx(0, -(CAP as i128), CAP);
    let bypass = run(&c, &call_v1(-2 * CAP as i128, &CallExt::default())).unwrap();
    assert_eq!(
        bypass.ret.exec_size,
        -2 * CAP as i128,
        "control: stale counter admits 2x cap (LP would end +2*cap)"
    );
    let fixed = run(&c, &call_v2(-2 * CAP as i128, 0, &CallExt::default())).unwrap();
    assert_eq!(fixed.ret.exec_size, -(CAP as i128), "clipped to the cap");
    assert_ne!(
        fixed.ret.flags & FLAG_PARTIAL_OK,
        0,
        "partial fill is flagged"
    );
    assert_eq!(fixed.inv_after, CAP as i128);
}

#[test]
fn v2_with_accurate_counter_is_identical_to_v1() {
    // No drift: counter == real. Every outcome (price, size, flags, stored counter) must be
    // byte-identical to the legacy path, for both kinds, both directions, under the cap edge.
    for kind in [0u8, 1] {
        for (inv, size) in [
            (0i128, 300i128),
            (-700, 400),
            (700, -400),
            (-900, 500),
            (900, -500),
        ] {
            let c = ctx(kind, inv, CAP);
            let a = run(&c, &call_v1(size, &CallExt::default())).unwrap();
            let b = run(&c, &call_v2(size, inv, &CallExt::default())).unwrap();
            assert_eq!(
                key(&a.ret),
                key(&b.ret),
                "kind {kind} inv {inv} size {size}"
            );
            assert_eq!(
                a.inv_after, b.inv_after,
                "kind {kind} inv {inv} size {size}"
            );
        }
    }
}

#[test]
fn v2_carries_headroom_and_band_like_v1() {
    let base = CallExt {
        headroom_q: Some(50),
        exec_band_bps: Some(25),
        ..CallExt::default()
    };
    let c = ctx(0, 0, 0);
    let a = run(&c, &call_v1(300, &base)).unwrap();
    let b = run(&c, &call_v2(300, 0, &base)).unwrap();
    assert_eq!(a.ret.exec_size, 50, "control: headroom clips the v1 call");
    assert_eq!(
        key(&a.ret),
        key(&b.ret),
        "v2 applies headroom/band identically"
    );
}

#[test]
fn skew_prices_off_the_real_position() {
    // skew widens the side that worsens inventory; a stale +cap counter makes a SELL look
    // worsening although the LP is really short (selling IMPROVES it)
    // M-1: the skew is normalised to max_inventory_abs (M == 0 is inert), so the context needs a
    // real cap; 10_000 = +10_000 bps at full inventory (900/CAP of it here), capped at 5000.
    let mut c = ctx(0, 900, CAP);
    c.skew_spread_mult_bps = 10_000;
    let stale = run(&c, &call_v1(-10, &CallExt::default())).unwrap();
    let real = run(&c, &call_v2(-10, -900, &CallExt::default())).unwrap();
    assert!(
        real.ret.exec_price_e6 > stale.ret.exec_price_e6,
        "a sell into a really-short LP is not skew-penalised (stale {} real {})",
        stale.ret.exec_price_e6,
        real.ret.exec_price_e6
    );
}

// ── batch (tag 3) ────────────────────────────────────────────────────────────────────

#[test]
fn batch_v2_carries_inventory_per_asset_across_legs() {
    // cap 1000, LP really flat on asset 0, counter stale at -1000.
    let c = ctx(0, -(CAP as i128), CAP);
    // two sells on asset 0 of 600 each: real path => first fills 600 (LP +600), second is
    // clipped to 400 => LP ends +1000 == cap. v2 legs both carry the PRE-batch position 0.
    let legs = [(0u16, -600i128), (0u16, -600i128)];
    let (_, inv) = run_batch(&c, &batch_bytes(&legs, Some(&[v2_block(0), v2_block(0)]))).unwrap();
    assert_eq!(
        inv, CAP as i128,
        "second leg sees +600 carried, clipped at the cap"
    );
    // negative control: v1 (no position) starts from the stale -1000 and lets both legs fill
    // fully (LP really ends +1200, past the cap)
    let v1 = vec![
        CallExt::default().encode().to_vec(),
        CallExt::default().encode().to_vec(),
    ];
    let (_, inv1) = run_batch(&c, &batch_bytes(&legs, Some(&v1))).unwrap();
    assert_eq!(
        inv1, 200,
        "control: stale counter -1000 - (-1200) = +200, both legs filled"
    );
}

#[test]
fn batch_v2_does_not_net_across_assets() {
    // percolator-match#8: asset A buy then asset B sell used to net the scalar to 0.
    let c = ctx(0, 0, CAP);
    // LP flat on both. Leg A: taker buys cap (LP -cap on A). Leg B: taker sells cap (LP +cap on
    // B). Then leg A again: taker buys 1 => LP would be -cap-1 on A => must zero-fill => batch
    // stores the A inventory (-cap) as its last state.
    let legs = [(0u16, CAP as i128), (1u16, -(CAP as i128)), (0u16, 1i128)];
    let (_, inv) = run_batch(
        &c,
        &batch_bytes(&legs, Some(&[v2_block(0), v2_block(0), v2_block(0)])),
    )
    .unwrap();
    assert_eq!(
        inv,
        -(CAP as i128),
        "third leg priced from asset-0 inventory, zero fill"
    );
    // control: legacy scalar netting lets the third leg fill (scalar 0 after leg B)
    let (_, inv1) = run_batch(&c, &batch_bytes(&legs, None)).unwrap();
    assert_eq!(
        inv1, -1,
        "control: cross-asset netting (scalar -cap + cap - 1)"
    );
}

#[test]
fn batch_rejects_mixed_or_wrong_length_extensions() {
    let c = ctx(0, 0, 0);
    let legs = [(0u16, 5i128), (0u16, 5i128)];
    // one v2 block + one v1 block = 64 bytes = neither 2*24 nor 2*40
    let mixed = vec![v2_block(0), CallExt::default().encode().to_vec()];
    assert!(run_batch(&c, &batch_bytes(&legs, Some(&mixed))).is_err());
    // 2*40 bytes but the second block says version 1
    let mut fake = v2_block(0);
    fake[0] = 1;
    assert!(run_batch(&c, &batch_bytes(&legs, Some(&[v2_block(0), fake]))).is_err());
    // control
    assert!(run_batch(&c, &batch_bytes(&legs, Some(&[v2_block(0), v2_block(0)]))).is_ok());
}
