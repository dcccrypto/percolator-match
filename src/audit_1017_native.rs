//! NATIVE (not Kani) companion of kani_audit_1017.rs: same assertions on the production pricing fns.
extern crate std;
use super::*;
    #[test]
    fn audit1017_native_pricing_bounds_random() {
        let mut x: u64 = 0x2545F4914F6CDD1D;
        let mut r = move || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x };
        let (mut checked, mut filled) = (0u64, 0u64);
        for i in 0..(1u64 << 24) {
            let kind = (i & 1) as u8;
            let mut ctx = MatcherCtx {
                magic: MATCHER_MAGIC, version: MATCHER_VERSION, kind, _pad0: [0; 3], lp_pda: [1; 32],
                trading_fee_bps: (r() % 1100) as u32, base_spread_bps: (r() % 1100) as u32,
                max_total_bps: (r() % 9100) as u32, impact_k_bps: (r() % 9100) as u32,
                liquidity_notional_e6: (r() >> (r() % 64)) as u128 + (kind as u128),
                max_fill_abs: if r() % 4 == 0 { (r() >> (r() % 64)) as u128 } else { i128::MAX as u128 },
                inventory_base: ((r() >> (r() % 64)) as i128) * if r() & 1 == 0 { 1 } else { -1 },
                last_oracle_price_e6: 0, last_exec_price_e6: 0,
                max_inventory_abs: if r() % 2 == 0 { 0 } else { (r() >> (r() % 64)) as u128 },
                insurance_accrued_e6: 0, fee_to_insurance_bps: 0,
                skew_spread_mult_bps: (r() % 10_100) as u16, _new_pad: [0; 4], lp_account_id: 0,
                insurance_fee_remainder_e6: 0, backing_fee_cap_bps: 0, _reserved: [0; 78],
            };
            if ctx.validate().is_err() { continue; }
            let oracle = (r() >> (r() % 64)).min(crate::ORACLE_PRICE_E6_MAX);
            let req = ((r() >> (r() % 100 % 64)) as i128) * if r() & 1 == 0 { 1 } else { -1 };
            let call = MatcherCall { req_id: 1, asset_index: 0, lp_account_id: 0, oracle_price_e6: oracle, req_size: req };
            let v3 = r() & 1 == 0;
            checked += 1;
            let inv_ok = ctx.max_inventory_abs == 0 || ctx.inventory_base.unsigned_abs() <= ctx.max_inventory_abs;
            match compute_execution_units(&ctx, &call, v3) {
                Err(e) => assert_eq!(e, ProgramError::ArithmeticOverflow),
                Ok((price, size, flags)) => {
                    let req_abs = req.unsigned_abs(); let fill = size.unsigned_abs();
                    assert!(flags & FLAG_VALID != 0 && fill <= req_abs && fill <= ctx.max_fill_abs);
                    assert!(size == 0 || (size > 0) == (req > 0));
                    if fill < req_abs { assert!(flags & FLAG_PARTIAL_OK != 0); }
                    if size == 0 { assert_eq!(price, oracle); continue; }
                    filled += 1;
                    let (o, m, p) = (oracle as u128, ctx.max_total_bps as u128, price as u128);
                    if size > 0 { assert!(p >= o && p * 10_000 <= o * (10_000 + m) + 9_999); }
                    else { assert!(p <= o && p * 10_000 + 9_999 >= o * (10_000 - m) && p >= 1); }
                    if ctx.max_inventory_abs != 0 && inv_ok {
                        assert!(ctx.inventory_base.checked_sub(size).is_some_and(|n| n.unsigned_abs() <= ctx.max_inventory_abs));
                    }
                }
            }
        }
        std::println!("native pricing sweep: validated ctx checked={checked} filled={filled}");
        assert!(checked > 1_000_000 && filled > 500_000);
    }
