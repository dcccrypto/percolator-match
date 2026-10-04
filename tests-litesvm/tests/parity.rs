//! Item 1, v1 parity: the v2 program must be byte-for-byte backward compatible with the deployed
//! v1 matcher (12bd671) for every v1-shaped input — kinds 0/1, legacy (all-zero) call
//! extension, legacy-length tag-3 batches, tag-4 backing fee cap.
//!
//! Method: two independent LiteSVM instances, one running the v1 .so and one the v2 .so,
//! same program id, same keys, same transactions. After EVERY transaction the full 320-byte
//! context accounts must be identical and the transaction outcome (Ok / exact error) must
//! match. Negative controls prove the comparator can see a difference.
mod common;
use common::*;
use percolator_match::v2::CallExt;
use percolator_match::vamm::InitParams;
use solana_pubkey::Pubkey;

struct Pair {
    v1: Env,
    v2: Env,
    lp: solana_keypair::Keypair,
    ctx: Pubkey,
}

impl Pair {
    fn new(ctx_tag: u8, p: &InitParams) -> Self {
        let mut v1 = Env::v1();
        let mut v2 = Env::v2();
        let lp = seeded_keypair(10);
        let ctx = Pubkey::new_from_array([ctx_tag; 32]);
        v1.alloc_ctx(ctx);
        v2.alloc_ctx(ctx);
        let r1 = v1.init(&lp, &ctx, p);
        let r2 = v2.init(&lp, &ctx, p);
        assert!(r1.is_ok() && r2.is_ok(), "init v1={r1:?} v2={r2:?}");
        let mut s = Pair { v1, v2, lp, ctx };
        s.assert_same("after init");
        s
    }

    fn assert_same(&mut self, what: &str) {
        let a = self.v1.ctx_data(&self.ctx);
        let b = self.v2.ctx_data(&self.ctx);
        assert_eq!(a.len(), 320);
        assert_eq!(a, b, "ctx bytes diverged: {what}");
    }

    /// Same raw instruction on both; outcomes must match exactly; ctx must match after.
    fn both(&mut self, data: Vec<u8>, what: &str) -> (TxResult, TxResult) {
        let r1 = self.v1.send(&self.lp, true, &self.ctx, data.clone());
        let r2 = self.v2.send(&self.lp, true, &self.ctx, data);
        match (&r1, &r2) {
            (Ok(m1), Ok(m2)) => {
                assert_eq!(
                    m1.return_data, m2.return_data,
                    "return data diverged: {what}"
                );
            }
            (Err(e1), Err(e2)) => assert_eq!(e1.err, e2.err, "errors diverged: {what}"),
            _ => panic!("outcome diverged: {what}: v1={r1:?} v2={r2:?}"),
        }
        self.assert_same(what);
        (r1, r2)
    }

    fn warp(&mut self, slot: u64) {
        self.v1.warp(slot);
        self.v2.warp(slot);
    }
}

/// Deterministic xorshift so the sequence is reproducible.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next() % (hi - lo + 1)
    }
}

fn configs() -> Vec<(&'static str, InitParams)> {
    let base = init_params(0);
    vec![
        ("k0 plain unlimited", base),
        (
            "k0 finite max_fill/max_inv + skew + insurance",
            InitParams {
                kind: 0,
                trading_fee_bps: 30,
                base_spread_bps: 50,
                max_total_bps: 600,
                max_fill_abs: 1_000,
                max_inventory_abs: 5_000,
                fee_to_insurance_bps: 2_500,
                skew_spread_mult_bps: 3,
                ..base
            },
        ),
        (
            "k1 unlimited",
            InitParams {
                kind: 1,
                trading_fee_bps: 5,
                base_spread_bps: 10,
                max_total_bps: 300,
                impact_k_bps: 500,
                liquidity_notional_e6: 10_000_000_000,
                ..base
            },
        ),
        (
            "k1 finite + skew + insurance, tiny depth (impact clamps)",
            InitParams {
                kind: 1,
                trading_fee_bps: 25,
                base_spread_bps: 15,
                max_total_bps: 1_000,
                impact_k_bps: 2_000,
                liquidity_notional_e6: 1_000_000_000,
                max_fill_abs: 700,
                max_inventory_abs: 3_000,
                fee_to_insurance_bps: 5_000,
                skew_spread_mult_bps: 7,
                lp_account_id: LP_ACCOUNT_ID,
            },
        ),
        (
            "k1 max_fill 0 (always zero-fill)",
            InitParams {
                kind: 1,
                impact_k_bps: 100,
                liquidity_notional_e6: 5_000_000_000,
                max_fill_abs: 0,
                ..base
            },
        ),
    ]
}

#[test]
fn v1_parity_tag0_sequence_all_configs() {
    for (ci, (name, p)) in configs().into_iter().enumerate() {
        let mut pr = Pair::new(0x30 + ci as u8, &p);
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15 ^ ci as u64);
        let mut price: u64 = 50_000_000;
        let mut fills = 0usize;
        let mut slot = 10u64;
        for i in 0..64u64 {
            // random walk price, mixed sides/sizes; a few extreme sizes.
            let step = rng.range(0, 400) as i64 - 200; // +-2%
            price = ((price as i64) * (10_000 + step) / 10_000).max(1) as u64;
            let mag = match i % 16 {
                7 => 1u64,
                11 => 10_000_000,
                13 => 0,
                _ => rng.range(1, 2_500),
            } as i128;
            let size = if rng.next() & 1 == 0 { mag } else { -mag };
            slot += rng.range(0, 50);
            pr.warp(slot);
            let c = Call::new(1000 + i, price, size);
            let (r1, _) = pr.both(c.encode(), &format!("{name} call #{i} px={price} sz={size}"));
            if r1.is_ok() {
                let ret = decode_return(&pr.v2.ctx_data(&pr.ctx)[..64]);
                if ret.exec_size != 0 {
                    fills += 1;
                }
            }
        }
        // Also the fixed error paths.
        let _ = pr.both(Call::new(9, 0, 5).encode(), "zero oracle");
        let _ = pr.both(Call::new(9, u64::MAX, 5).encode(), "oracle > max");
        let _ = pr.both(Call::new(9, 1_000_000, i128::MIN).encode(), "i128::MIN size");
        let mut bad_lp = Call::new(9, 1_000_000, 5);
        bad_lp.lp_id ^= 1;
        let _ = pr.both(bad_lp.encode(), "wrong lp_account_id");
        let mut short = Call::new(9, 1_000_000, 5).encode();
        short.truncate(66);
        let _ = pr.both(short, "66-byte call");
        let expect_fills = p.max_fill_abs != 0;
        assert_eq!(
            fills > 30,
            expect_fills,
            "{name}: sequence must actually exercise fills (fills={fills})"
        );
        let st = pr.v2.ctx_struct(&pr.ctx);
        if p.fee_to_insurance_bps > 0 {
            assert!(st.insurance_accrued_e6 > 0, "{name}: insurance path must be exercised");
        }
        println!(
            "parity {name}: 64 calls, {fills} non-zero fills, final inventory {}, insurance {}",
            st.inventory_base, st.insurance_accrued_e6
        );
    }
}

#[test]
fn v1_parity_tag3_batch_legacy_length() {
    for (ci, (name, p)) in configs().into_iter().enumerate() {
        let mut pr = Pair::new(0x50 + ci as u8, &p);
        let mut rng = Rng(0xdead_beef ^ ci as u64);
        for round in 0..12u64 {
            let n = 1 + (round as usize % 16);
            let prices = [1_000_000u64, 25_000_000, 3, 999_999_999];
            let legs = (0..n)
                .map(|k| {
                    let a = (rng.next() % 4) as u16;
                    let mag = rng.range(0, 3_000) as i128;
                    let sz = if rng.next() & 1 == 0 { mag } else { -mag };
                    Leg::new(a, prices[a as usize] + round, sz + k as i128)
                })
                .collect();
            let b = Batch::legacy(77 + round, legs);
            let _ = pr.both(b.encode(), &format!("{name} batch round {round} n={n}"));
        }
        // inconsistent price on the same asset -> both Custom(8001)
        let b = Batch::legacy(5, vec![Leg::new(0, 1_000_000, 5), Leg::new(0, 1_000_001, 5)]);
        let (r1, _) = pr.both(b.encode(), "inconsistent leg price");
        assert_eq!(ix_err(&r1.unwrap_err()), custom(8001));
        // 17 legs -> both invalid
        let b = Batch::legacy(5, vec![Leg::new(0, 1_000_000, 1); 17]);
        let _ = pr.both(b.encode(), "17 legs");
    }
}

#[test]
fn v1_parity_tag4_backing_fee_cap() {
    let mut pr = Pair::new(0x70, &configs()[1].1);
    for cap in [0u16, 1, 1234, 10_000] {
        let (r, _) = pr.both(vec![4, cap as u8, (cap >> 8) as u8], &format!("tag4 cap {cap}"));
        assert!(r.is_ok());
        assert_eq!(
            u16::from_le_bytes(pr.v2.ctx_data(&pr.ctx)[240..242].try_into().unwrap()),
            cap
        );
        // subsequent call carries the cap in flags bits 8..21 identically
        let _ = pr.both(Call::new(cap as u64, 1_000_000, 10).encode(), "call after tag4");
        let ret = decode_return(&pr.v2.ctx_data(&pr.ctx)[..64]);
        assert_eq!(ret.backing_fee_cap_bps(), cap);
    }
    let (r, _) = pr.both(vec![4, 0x11, 0x27], "tag4 cap 10001");
    assert!(r.is_err());
    // wrong signer on tag 4: both reject identically
    let other = seeded_keypair(99);
    let r1 = pr.v1.send(&other, true, &pr.ctx, vec![4, 1, 0]);
    let r2 = pr.v2.send(&other, true, &pr.ctx, vec![4, 1, 0]);
    assert_eq!(r1.unwrap_err().err, r2.unwrap_err().err);
    pr.assert_same("after wrong-signer tag4");
}

/// NEGATIVE CONTROLS for the parity comparator:
/// (a) one differing input on one side is detected (the comparator is not vacuous — e.g.
///     not accidentally comparing an instance against itself);
/// (b) the two instances are genuinely different programs: v1 rejects a v2 call extension
///     that v2 accepts, and v1 rejects tag 5.
#[test]
fn neg_parity_comparator_detects_divergence() {
    let mut pr = Pair::new(0x71, &init_params(0));
    let a = Call::new(1, 1_000_000, 100);
    let b = Call::new(1, 1_000_000, 101); // one variable changed
    pr.v1.send(&pr.lp, true, &pr.ctx, a.encode()).unwrap();
    pr.v2.send(&pr.lp, true, &pr.ctx, b.encode()).unwrap();
    assert_ne!(
        pr.v1.ctx_data(&pr.ctx),
        pr.v2.ctx_data(&pr.ctx),
        "comparator must see a one-unit size difference"
    );

    let mut pr = Pair::new(0x72, &init_params(0));
    let ext = Call::new(2, 1_000_000, 100).ext(CallExt {
        headroom_q: Some(u64::MAX),
        mark_slot: None,
        accepts_fee_request: false,
        ..CallExt::default()
    });
    let r1 = pr.v1.send(&pr.lp, true, &pr.ctx, ext.encode());
    let r2 = pr.v2.send(&pr.lp, true, &pr.ctx, ext.encode());
    assert_eq!(
        ix_err(&r1.unwrap_err()),
        solana_instruction::error::InstructionError::InvalidInstructionData,
        "v1 must reject a non-zero call extension (proves the v1 .so really is v1)"
    );
    assert!(r2.is_ok(), "v2 accepts ext_version 1: {r2:?}");
    let t5 = common::op_cap(5);
    let r1 = pr.v1.configure_lp_pda(&pr.lp, &pr.ctx, &t5);
    assert!(r1.is_err(), "v1 has no tag 5");

    let h1 = std::fs::read(v1_so_path()).unwrap();
    let h2 = std::fs::read(v2_so_path()).unwrap();
    assert_ne!(h1, h2, "v1 and v2 .so must be different binaries");
}
