//! Items 10 (call-extension parsing, fail closed) and 12 (negotiated requested-fee return bits).
mod common;
use common::*;
use percolator_match::v2::CallExt;
use percolator_match::vamm::InitParams;
use percolator_match::{
    FLAG_BACKING_FEE_CAP_MASK, FLAG_PARTIAL_OK, FLAG_REJECTED, FLAG_REQUESTED_FEE_MASK,
    FLAG_VALID,
};
use solana_instruction::error::InstructionError;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;

const P: u64 = 1_000_000;
/// What the deployed v18.2 wrapper's validate_matcher_return accepts.
const V182_KNOWN: u32 = FLAG_VALID | FLAG_PARTIAL_OK | FLAG_REJECTED | FLAG_BACKING_FEE_CAP_MASK;

fn setups() -> Vec<(u8, Env, Keypair, Pubkey)> {
    [0u8, 1, 2]
        .into_iter()
        .map(|k| {
            let mut env = Env::v2();
            let lp = seeded_keypair(1);
            let ctx = env.new_ctx(&lp, &init_params(k));
            env.warp(10);
            (k, env, lp, ctx)
        })
        .collect()
}

fn v1ext(flags: u8) -> [u8; 24] {
    let mut b = [0u8; 24];
    b[0] = 1;
    b[1] = flags;
    b
}

// -----------------------------------------------------------------------------
// 10. Extension parsing
// -----------------------------------------------------------------------------

#[test]
fn ext_malformed_rejected_invalid_instruction_data() {
    let mut bad: Vec<(String, [u8; 24])> = vec![];
    for v in [2u8, 3, 0x80, 0xff] {
        let mut b = v1ext(0);
        b[0] = v;
        bad.push((format!("ext_version {v}"), b));
    }
    for bit in 5..8 {
        bad.push((format!("unknown flag bit {bit}"), v1ext(1 << bit)));
    }
    for i in [20usize, 21, 22, 23] {
        let mut b = v1ext(0b1_1111);
        b[i] = 1;
        bad.push((format!("reserved byte {i} nonzero"), b));
    }
    for i in [2usize, 3] {
        let mut b = v1ext(0b0_1111); // EXEC_BAND flag not set
        b[i] = 1;
        bad.push((format!("exec_band byte {i} without EXEC_BAND"), b));
    }
    for i in 12..20 {
        let mut b = v1ext(0); // HEADROOM flag not set
        b[i] = 1;
        bad.push((format!("headroom byte {i} without HEADROOM"), b));
    }
    for i in 4..12 {
        let mut b = v1ext(0b101); // MARK_SLOT flag not set
        b[i] = 1;
        bad.push((format!("mark_slot byte {i} without MARK_SLOT"), b));
    }
    for i in 1..24 {
        let mut b = [0u8; 24]; // version 0: every byte must be zero
        b[i] = 1;
        bad.push((format!("legacy ext byte {i} nonzero"), b));
    }
    for (k, mut env, lp, ctx) in setups() {
        let before = env.ctx_data(&ctx);
        for (what, b) in &bad {
            let e = expect_err(env.call(&lp, &ctx, &Call::new(1, P, 10).ext_raw(*b)));
            assert_eq!(e, InstructionError::InvalidInstructionData, "kind {k}: {what}");
            // same extension on a batch leg
            let mut leg = Leg::new(0, P, 10);
            leg.ext = *b;
            let e = expect_err(env.batch(&lp, &ctx, &Batch::with_ext(1, vec![Leg::new(0, P, 1), leg])));
            assert_eq!(e, InstructionError::InvalidInstructionData, "kind {k} batch: {what}");
        }
        assert_eq!(env.ctx_data(&ctx), before, "kind {k}: every rejection left ctx untouched");
    }
}

/// NEGATIVE CONTROLS: the same bytes with the corresponding flag set (or the empty v1
/// ext) are accepted — the rejection is the flag/field rule, not the byte position.
#[test]
fn neg_ext_wellformed_accepted() {
    let mut good: Vec<(&str, [u8; 24])> = vec![];
    good.push(("empty v1 ext", v1ext(0)));
    good.push(("known flag bit 2 (ACCEPTS_FEE_REQUEST)", v1ext(0b100)));
    good.push(("known flag bit 3 (TAKER_REDUCING)", v1ext(0b1000)));
    let mut b = v1ext(0b1_0000);
    b[2..4].copy_from_slice(&5_000u16.to_le_bytes());
    good.push(("exec_band bytes with EXEC_BAND flag", b));
    let mut b = v1ext(0b001);
    b[12..20].copy_from_slice(&5_000u64.to_le_bytes());
    good.push(("headroom with HEADROOM flag", b));
    let mut b = v1ext(0b010);
    b[4..12].copy_from_slice(&10u64.to_le_bytes());
    good.push(("mark_slot with MARK_SLOT flag", b));
    let mut b = v1ext(0b1_1111);
    b[2..4].copy_from_slice(&9_000u16.to_le_bytes());
    b[4..12].copy_from_slice(&10u64.to_le_bytes());
    b[12..20].copy_from_slice(&u64::MAX.to_le_bytes());
    good.push(("all five", b));
    for (k, mut env, lp, ctx) in setups() {
        for (i, (what, b)) in good.iter().enumerate() {
            let r = env.call(&lp, &ctx, &Call::new(i as u64, P, 10).ext_raw(*b));
            assert!(r.is_ok(), "kind {k}: {what}: {r:?}");
            assert_eq!(r.unwrap().0.exec_size, 10);
        }
    }
}

#[test]
fn batch_ext_trailer_length_must_be_exact() {
    let mut env = Env::v2();
    let lp = seeded_keypair(1);
    let ctx = env.new_ctx(&lp, &init_params(0));
    let b = Batch::with_ext(1, vec![Leg::new(0, P, 1); 3]);
    let good = b.encode();
    assert!(env.call_raw(&lp, &ctx, good.clone()).is_ok());
    for delta in [-1i64, 1, -24, 24] {
        let mut d = good.clone();
        if delta < 0 {
            d.truncate((d.len() as i64 + delta) as usize);
        } else {
            d.extend(std::iter::repeat_n(0u8, delta as usize));
        }
        // -24 -> neither legacy (18+78) nor 3 exts; +24 likewise
        let e = expect_err(env.call_raw(&lp, &ctx, d));
        assert_eq!(e, InstructionError::InvalidInstructionData, "delta {delta}");
    }
}

// -----------------------------------------------------------------------------
// 12. Requested-fee return bits (22..31)
// -----------------------------------------------------------------------------

fn fee_ext(accepts: bool, headroom: Option<u64>) -> CallExt {
    CallExt {
        headroom_q: headroom,
        mark_slot: None,
        accepts_fee_request: accepts,
        ..CallExt::default()
    }
}

fn want_fee(oracle: u64, exec: u64) -> u32 {
    let d = (exec as i128 - oracle as i128).unsigned_abs();
    (d * 10_000).div_ceil(oracle as u128).min(1023) as u32
}

#[test]
fn requested_fee_bits_set_when_negotiated_and_filled() {
    for (k, mut env, lp, ctx) in setups() {
        for (i, (px, sz)) in [(P, 100i128), (P, -100), (1_234_567, 77), (987_654_321, -5)]
            .into_iter()
            .enumerate()
        {
            let (r, _) = env
                .call(&lp, &ctx, &Call::new(i as u64, px, sz).ext(fee_ext(true, None)))
                .unwrap();
            assert_eq!(r.exec_size, sz);
            assert_eq!(
                r.requested_fee_bps(),
                want_fee(px, r.exec_price_e6),
                "kind {k} px {px} sz {sz}"
            );
            assert!(r.requested_fee_bps() > 0);
            assert_eq!(r.flags >> 22, r.requested_fee_bps());
        }
        // kind 0 quotes exactly 30 bps at a round price
        if k == 0 {
            let (r, _) = env
                .call(&lp, &ctx, &Call::new(9, P, 100).ext(fee_ext(true, None)))
                .unwrap();
            assert_eq!(r.requested_fee_bps(), 30);
        }
    }
}

#[test]
fn requested_fee_coexists_with_backing_cap_bits() {
    let mut env = Env::v2();
    let lp = seeded_keypair(1);
    let ctx = env.new_ctx(&lp, &init_params(0));
    env.configure_lp_pda(&lp, &ctx, &op_cap(10_000)).unwrap();
    let (r, _) = env
        .call(&lp, &ctx, &Call::new(1, P, 100).ext(fee_ext(true, None)))
        .unwrap();
    assert_eq!(r.backing_fee_cap_bps(), 10_000);
    assert_eq!(r.requested_fee_bps(), 30);
    assert_eq!(r.flags & 0xff, FLAG_VALID);
}

#[test]
fn requested_fee_saturates_at_1023() {
    let mut env = Env::v2();
    let lp = seeded_keypair(1);
    let ctx = env.new_ctx(
        &lp,
        &InitParams {
            trading_fee_bps: 0,
            base_spread_bps: 2_000,
            max_total_bps: 2_000,
            ..init_params(0)
        },
    );
    let (r, _) = env
        .call(&lp, &ctx, &Call::new(1, P, 100).ext(fee_ext(true, None)))
        .unwrap();
    assert_eq!(r.exec_price_e6, ask(P, 2_000));
    assert_eq!(r.requested_fee_bps(), 1023, "quoted 2000 bps, channel saturates");
}

/// NEGATIVE CONTROLS: (a) legacy ext -> no fee bits and flags within v18.2 KNOWN_FLAGS;
/// (b) ext present but accepts_fee_request = false -> no fee bits; (c) zero-fill with
/// accepts_fee_request = true -> no fee bits.
#[test]
fn neg_requested_fee_absent_without_negotiation_or_fill() {
    for (k, mut env, lp, ctx) in setups() {
        env.configure_lp_pda(&lp, &ctx, &op_cap(9_999)).unwrap();
        let (r, _) = env.call(&lp, &ctx, &Call::new(1, P, 100)).unwrap();
        assert_eq!(r.flags & FLAG_REQUESTED_FEE_MASK, 0, "kind {k} (a) legacy");
        assert_eq!(r.flags & !V182_KNOWN, 0, "kind {k} (a) flags within v18.2 KNOWN");
        assert!(r.exec_price_e6 > P, "a real spread was quoted");

        let (r, _) = env
            .call(&lp, &ctx, &Call::new(2, P, 100).ext(fee_ext(false, Some(u64::MAX))))
            .unwrap();
        assert_eq!(r.exec_size, 100);
        assert_eq!(r.flags & FLAG_REQUESTED_FEE_MASK, 0, "kind {k} (b) not negotiated");
        assert_eq!(r.flags & !V182_KNOWN, 0);

        let (r, _) = env
            .call(&lp, &ctx, &Call::new(3, P, 100).ext(fee_ext(true, Some(0))))
            .unwrap();
        assert_eq!(r.exec_size, 0);
        assert_eq!(r.flags & FLAG_REQUESTED_FEE_MASK, 0, "kind {k} (c) zero fill");

        // CONTROL for (c): identical but headroom 100 -> bits present
        let (r, _) = env
            .call(&lp, &ctx, &Call::new(4, P, 100).ext(fee_ext(true, Some(100))))
            .unwrap();
        assert!(r.requested_fee_bps() > 0, "kind {k}");
    }
}

#[test]
fn requested_fee_batch_legs() {
    for (k, mut env, lp, ctx) in setups() {
        let legs = vec![
            Leg::new(0, P, 100).ext(fee_ext(true, None)),       // negotiated, fills
            Leg::new(0, P, -100).ext(fee_ext(false, None)),     // not negotiated
            Leg::new(0, P, 100).ext(fee_ext(true, Some(0))),    // negotiated, zero fill
            Leg::new(0, P, -50).ext(fee_ext(true, Some(1_000))), // negotiated, fills
        ];
        let (rets, _) = env.batch(&lp, &ctx, &Batch::with_ext(1, legs)).unwrap();
        assert_eq!(rets[0].requested_fee_bps(), want_fee(P, rets[0].exec_price_e6), "kind {k}");
        assert!(rets[0].requested_fee_bps() > 0);
        assert_eq!(rets[1].flags & FLAG_REQUESTED_FEE_MASK, 0);
        assert_eq!(rets[2].exec_size, 0);
        assert_eq!(rets[2].flags & FLAG_REQUESTED_FEE_MASK, 0);
        assert_eq!(rets[3].requested_fee_bps(), want_fee(P, rets[3].exec_price_e6));
        assert!(rets[3].requested_fee_bps() > 0);
        // legacy-length batch never carries the bits
        let (rets, _) = env
            .batch(&lp, &ctx, &Batch::legacy(2, vec![Leg::new(0, P, 10); 4]))
            .unwrap();
        assert!(rets.iter().all(|r| r.flags & !V182_KNOWN == 0));
    }
}

/// Observation (reported, not asserted as a bug): at tiny oracle prices the ceil-rounded
/// exec price makes the requested fee far exceed the LP's configured spread.
#[test]
fn requested_fee_rounding_at_tiny_oracle_price() {
    let mut env = Env::v2();
    let lp = seeded_keypair(1);
    let ctx = env.new_ctx(&lp, &init_params(0)); // quotes 30 bps
    let (r, _) = env
        .call(&lp, &ctx, &Call::new(1, 3, 100).ext(fee_ext(true, None)))
        .unwrap();
    println!(
        "oracle 3, configured 30 bps: exec {} requested_fee {} bps",
        r.exec_price_e6,
        r.requested_fee_bps()
    );
    assert_eq!(r.exec_price_e6, 4);
    assert_eq!(r.requested_fee_bps(), 1023);
}
