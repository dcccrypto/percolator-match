//! v2.2 full audit 2026-10-17, workstream K: matcher PRODUCTION-function pricing bounds.
//! cfg(kani) only. The pre-existing matcher proofs in `vamm.rs` are model-only (they re-state the
//! formulas on harness locals; `proof_impact_bps_no_overflow` even asserts `x <= u128::MAX`).
//! These call the REAL `compute_execution_units` (-> `compute_passive_execution` /
//! `compute_vamm_execution` -> `check_inventory_limit`, `compute_skew_extra_bps_units`).
//! The context is any state that production `validate()` accepts (the real validator is the
//! assumption, nothing narrower); the oracle is the full u64 and the request any i128.
use super::*;

fn any_ctx(kind: u8) -> MatcherCtx {
    MatcherCtx {
        magic: MATCHER_MAGIC,
        version: MATCHER_VERSION,
        kind,
        _pad0: [0; 3],
        lp_pda: [1; 32],
        trading_fee_bps: kani::any(),
        base_spread_bps: kani::any(),
        max_total_bps: kani::any(),
        impact_k_bps: kani::any(),
        liquidity_notional_e6: kani::any(),
        max_fill_abs: kani::any(),
        inventory_base: kani::any(),
        last_oracle_price_e6: 0,
        last_exec_price_e6: 0,
        max_inventory_abs: kani::any(),
        insurance_accrued_e6: 0,
        fee_to_insurance_bps: 0,
        skew_spread_mult_bps: kani::any(),
        _new_pad: [0; 4],
        lp_account_id: 0,
        insurance_fee_remainder_e6: 0,
        backing_fee_cap_bps: 0,
        _reserved: [0; 78],
    }
}

fn check_exec(kind: u8) {
    let ctx = any_ctx(kind);
    kani::assume(ctx.validate().is_ok());
    let oracle: u64 = kani::any();
    let req: i128 = kani::any();
    let call = MatcherCall { req_id: 1, asset_index: 0, lp_account_id: 0, oracle_price_e6: oracle, req_size: req };
    let v3: bool = kani::any();
    // Pre-state invariant of an LP that has been trading under the cap.
    let inv_ok = ctx.max_inventory_abs == 0 || ctx.inventory_base.unsigned_abs() <= ctx.max_inventory_abs;
    match compute_execution_units(&ctx, &call, v3) {
        Err(e) => {
            // the only error production raises on a validated Passive/Vamm ctx
            assert!(e == ProgramError::ArithmeticOverflow);
            kani::cover!(true, "error path reached (overflow / zero price)");
        }
        Ok((price, size, flags)) => {
            let req_abs = req.unsigned_abs();
            let fill = size.unsigned_abs();
            assert!(flags & FLAG_VALID != 0);
            // never fills more than asked or than the per-call cap; sign follows the request
            assert!(fill <= req_abs);
            assert!(fill <= ctx.max_fill_abs);
            assert!(size == 0 || (size > 0) == (req > 0));
            // a clipped fill must be flagged partial-OK (GH#452)
            if fill < req_abs {
                assert!(flags & FLAG_PARTIAL_OK != 0);
            }
            if size == 0 {
                assert!(price == oracle);
                kani::cover!(req != 0, "zero fill of a non-zero request");
            } else {
                // price within [oracle*(1 - max_total), oracle*(1 + max_total)], rounded toward the LP
                let o = oracle as u128;
                let m = ctx.max_total_bps as u128;
                let p = price as u128;
                if size > 0 {
                    assert!(p >= o);
                    assert!(p * 10_000 <= o * (10_000 + m) + 9_999);
                    kani::cover!(p > o, "buy strictly above oracle");
                    kani::cover!(p * 10_000 + 10_000 > o * (10_000 + m) && m > 0, "buy at the max_total cap");
                } else {
                    assert!(p <= o);
                    assert!(p * 10_000 + 9_999 >= o * (10_000 - m));
                    assert!(p >= 1);
                    kani::cover!(p < o, "sell strictly below oracle");
                }
                if fill < req_abs {
                    kani::cover!(ctx.max_fill_abs < req_abs, "clipped by max_fill_abs");
                    kani::cover!(ctx.max_inventory_abs != 0 && ctx.max_fill_abs >= req_abs, "clipped by the inventory cap");
                }
                // inventory cap: a LP that starts inside the cap ends inside the cap
                if ctx.max_inventory_abs != 0 && inv_ok {
                    let new_inv = ctx.inventory_base.checked_sub(size);
                    assert!(new_inv.is_some_and(|n| n.unsigned_abs() <= ctx.max_inventory_abs));
                    kani::cover!(true, "inventory-capped fill ended within the cap");
                }
            }
        }
    }
}

/// Over-approximation of `compute_skew_extra_bps_units` for K-M1/K-M2: any value in [0, 5000]. The real
/// function is `min(extra, 5000)` (or 0), so every value it can return lies in this range; K-M3 proves that
/// on the REAL function. The bounds in K-M1/K-M2 hold for EVERY skew value in the range, so nothing is lost by
/// not carrying the u128 variable division `inv * mult / max_inventory_abs` through the price proofs.
fn skew_any_le_cap(_ctx: &MatcherCtx, _is_buy: bool, _v3_units: bool) -> u128 {
    let x: u128 = kani::any();
    kani::assume(x <= 5000);
    x
}

/// K-M1: production Passive pricing: bounds, fill, flags, inventory cap.
#[kani::proof]
#[kani::unwind(81)]
#[kani::stub(super::compute_skew_extra_bps_units, skew_any_le_cap)]
fn kani_audit1017_m1_passive_execution_bounds() {
    check_exec(MatcherKind::Passive as u8);
}

/// K-M2: production vAMM pricing (impact clamped by max_total): same bounds.
#[kani::proof]
#[kani::unwind(81)]
#[kani::stub(super::compute_skew_extra_bps_units, skew_any_le_cap)]
fn kani_audit1017_m2_vamm_execution_bounds() {
    check_exec(MatcherKind::Vamm as u8);
}

/// K-M3: the REAL skew surcharge is 0 unless the trade worsens the LP's inventory and a multiplier is set,
/// and never exceeds 5000 bps (the cap the K-M1/K-M2 stub relies on).
#[kani::proof]
#[kani::unwind(3)]
fn kani_audit1017_m3_skew_extra_capped_and_side_correct() {
    let kind: u8 = if kani::any() { MatcherKind::Vamm as u8 } else { MatcherKind::Passive as u8 };
    let ctx = any_ctx(kind);
    let is_buy: bool = kani::any();
    let v3: bool = kani::any();
    let e = compute_skew_extra_bps_units(&ctx, is_buy, v3);
    assert!(e <= 5000);
    if ctx.skew_spread_mult_bps == 0 {
        assert!(e == 0);
    }
    // buy worsens only a short LP; sell worsens only a long LP
    if (is_buy && ctx.inventory_base >= 0) || (!is_buy && ctx.inventory_base <= 0) {
        assert!(e == 0);
        kani::cover!(ctx.skew_spread_mult_bps > 0, "non-worsening side pays no surcharge though a multiplier is set");
    }
    kani::cover!(e > 0 && e < 5000, "surcharge strictly inside the cap");
    kani::cover!(e == 5000, "cap binds");
}
