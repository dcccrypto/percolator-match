//! Item 11: compute units of the compiled program. Printed for the report; fails if any single
//! instruction exceeds 200k CU (the default per-instruction budget).
mod common;
use common::*;
use percolator_match::v2::CallExt;
use percolator_match::vamm::InitParams;

const LIMIT: u64 = 200_000;

fn warm_kind2_params() -> InitParams {
    // every kind-2 pricing term live: impact, skew (finite ref via max_inventory), insurance
    InitParams {
        kind: 2,
        trading_fee_bps: 10,
        base_spread_bps: 20,
        max_total_bps: 800,
        impact_k_bps: 5_000,
        liquidity_notional_e6: 10_000_000_000_000,
        max_fill_abs: u128::MAX,
        max_inventory_abs: 1_000_000_000,
        fee_to_insurance_bps: 2_000,
        skew_spread_mult_bps: 200,
        lp_account_id: LP_ACCOUNT_ID,
    }
}

fn full_ext(slot: u64) -> CallExt {
    CallExt {
        headroom_q: Some(u64::MAX),
        mark_slot: Some(slot),
        accepts_fee_request: true,
        ..CallExt::default()
    }
}

#[test]
fn compute_units_report() {
    let mut rows: Vec<(String, u64)> = vec![];
    for (label, mut env) in [("v1", Env::v1()), ("v2", Env::v2())] {
        let lp = seeded_keypair(1);
        for kind in [0u8, 1] {
            let ctx = env.new_ctx(&lp, &init_params(kind));
            let (_, m) = env.call(&lp, &ctx, &Call::new(1, 1_000_000, 12_345)).unwrap();
            rows.push((format!("{label} tag0 legacy kind {kind}"), m.compute_units_consumed));
            let (_, m) = env
                .batch(&lp, &ctx, &Batch::legacy(2, vec![Leg::new(0, 1_000_000, 7); 11]))
                .unwrap();
            rows.push((
                format!("{label} tag3 legacy 11 legs kind {kind}"),
                m.compute_units_consumed,
            ));
        }
    }

    let mut env = Env::v2();
    let lp = seeded_keypair(1);
    let ctx = env.new_ctx(&lp, &warm_kind2_params());
    // warm the estimator past its default warmup (8 samples at 25-slot spacing)
    let mut slot = 1_000u64;
    for i in 0..12u64 {
        slot += 25;
        env.warp(slot);
        let px = if i % 2 == 0 { 1_000_000 } else { 1_010_000 };
        let sz = if i % 2 == 0 { 500 } else { -500 };
        env.call(&lp, &ctx, &Call::new(i, px, sz)).unwrap();
    }
    assert_eq!(ctx_v2_raw(&env.ctx_data(&ctx))[14], 0, "estimator warm");
    // single call that also takes an estimator sample (worst single-leg path)
    slot += 25;
    env.warp(slot);
    let (r, m) = env
        .call(&lp, &ctx, &Call::new(100, 1_003_000, 2_000).ext(full_ext(slot)))
        .unwrap();
    assert_eq!(r.exec_size, 2_000);
    rows.push(("v2 tag0 kind 2 warm, full ext".into(), m.compute_units_consumed));
    let (_, m) = env.call(&lp, &ctx, &Call::new(101, 1_003_000, -300)).unwrap();
    rows.push(("v2 tag0 kind 2 warm, legacy ext".into(), m.compute_units_consumed));

    slot += 25;
    env.warp(slot);
    let legs = (0..11)
        .map(|i| Leg::new(0, 1_004_000, if i % 3 == 0 { -700 } else { 900 }).ext(full_ext(slot)))
        .collect();
    let (rets, m) = env.batch(&lp, &ctx, &Batch::with_ext(200, legs)).unwrap();
    assert!(rets.iter().all(|r| r.exec_size != 0));
    rows.push(("v2 tag3 kind 2 warm, 11 legs + ext".into(), m.compute_units_consumed));
    let legs16 = (0..16)
        .map(|i| Leg::new(0, 1_004_000, if i % 2 == 0 { -70 } else { 90 }).ext(full_ext(slot)))
        .collect();
    let (_, m) = env.batch(&lp, &ctx, &Batch::with_ext(201, legs16)).unwrap();
    rows.push(("v2 tag3 kind 2 warm, 16 legs + ext".into(), m.compute_units_consumed));

    // Worst case for the kind-2 size clip (203a4aa binary-searches f* over [0, request]):
    // requests far above the feasible size, so every leg runs the full search.
    let huge: i128 = 100_000_000_000_000_000_000_000_000; // 1e29 (notional still fits u128)
    slot += 25;
    env.warp(slot);
    let (r, m) = env
        .call(&lp, &ctx, &Call::new(300, 1_004_000, huge).ext(full_ext(slot)))
        .unwrap();
    assert!(r.exec_size > 0 && r.exec_size < huge, "clipped");
    rows.push(("v2 tag0 kind 2 clipped 1e29 request".into(), m.compute_units_consumed));
    let legs16 = (0..16)
        .map(|i| Leg::new(0, 1_004_000, if i % 2 == 0 { huge } else { -huge }).ext(full_ext(slot)))
        .collect();
    let (rets, m) = env.batch(&lp, &ctx, &Batch::with_ext(301, legs16)).unwrap();
    assert!(rets.iter().all(|r| r.exec_size.unsigned_abs() < huge as u128));
    rows.push(("v2 tag3 kind 2 16 clipped 1e29 legs".into(), m.compute_units_consumed));

    println!("\n=== compute units ===");
    for (k, v) in &rows {
        println!("{k:<40} {v:>8}");
    }
    for (k, v) in &rows {
        assert!(*v > 0, "{k}: CU must be measured");
        assert!(*v <= LIMIT, "{k}: {v} CU exceeds {LIMIT}");
    }
}
