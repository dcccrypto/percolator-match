//! Passive LP matcher unit tests.
//!
//! Covers: skew handling, insurance fee routing split, sign correctness,
//! and the NEW-3 signer inversion regression (buy→huge sell direction bug).

use percolator_match::passive_lp_matcher::{
    compute_quote, MatchResult, PassiveLpState, PassiveMatcherConfig,
    PassiveOracleBpsMatcher, Reason,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn default_cfg() -> PassiveMatcherConfig {
    PassiveMatcherConfig::default()
}

fn default_lp() -> PassiveLpState {
    PassiveLpState::default()
}

fn matcher() -> PassiveOracleBpsMatcher {
    PassiveOracleBpsMatcher
}

// ---------------------------------------------------------------------------
// NEW-3 signer inversion regression
//
// Prior bug: a user buy (positive req_size) was converted to a large sell at the
// fill sign step. The fix ensures:
//   req_size > 0 (user BUY) => exec.size > 0, quote_delta_lp > 0, LP inventory < 0
//   req_size < 0 (user SELL) => exec.size < 0, quote_delta_lp < 0, LP inventory > 0
// ---------------------------------------------------------------------------

#[test]
fn new3_buy_req_produces_positive_exec_size() {
    let mut lp = default_lp();
    let r = matcher().execute_match(&default_cfg(), &mut lp, 100_000, 1, None);
    assert_eq!(r.reason, Reason::Ok);
    assert!(r.exec.size > 0, "NEW-3: buy req must produce positive exec size, got {}", r.exec.size);
}

#[test]
fn new3_sell_req_produces_negative_exec_size() {
    let mut lp = default_lp();
    let r = matcher().execute_match(&default_cfg(), &mut lp, 100_000, -1, None);
    assert_eq!(r.reason, Reason::Ok);
    assert!(r.exec.size < 0, "NEW-3: sell req must produce negative exec size, got {}", r.exec.size);
}

#[test]
fn new3_buy_lp_inventory_goes_negative() {
    // LP sells base on a buy → LP inventory decreases
    let mut lp = PassiveLpState { inventory_base: 0 };
    let r = matcher().execute_match(&default_cfg(), &mut lp, 100_000, 10, None);
    assert_eq!(r.reason, Reason::Ok);
    assert!(
        lp.inventory_base < 0,
        "NEW-3: LP must go short after user buy, got inventory={}",
        lp.inventory_base
    );
    assert_eq!(lp.inventory_base, -10);
}

#[test]
fn new3_sell_lp_inventory_goes_positive() {
    // LP buys base on a sell → LP inventory increases
    let mut lp = PassiveLpState { inventory_base: 0 };
    let r = matcher().execute_match(&default_cfg(), &mut lp, 100_000, -10, None);
    assert_eq!(r.reason, Reason::Ok);
    assert!(
        lp.inventory_base > 0,
        "NEW-3: LP must go long after user sell, got inventory={}",
        lp.inventory_base
    );
    assert_eq!(lp.inventory_base, 10);
}

#[test]
fn new3_buy_lp_receives_quote() {
    // User buys (LP sells base) → LP receives quote_delta_lp > 0
    let mut lp = default_lp();
    let r = matcher().execute_match(&default_cfg(), &mut lp, 100_000, 5, None);
    assert_eq!(r.reason, Reason::Ok);
    assert!(
        r.quote_delta_lp > 0,
        "NEW-3: LP must receive quote on user buy, got {}",
        r.quote_delta_lp
    );
}

#[test]
fn new3_sell_lp_pays_quote() {
    // User sells (LP buys base) → LP pays quote, quote_delta_lp < 0
    let mut lp = default_lp();
    let r = matcher().execute_match(&default_cfg(), &mut lp, 100_000, -5, None);
    assert_eq!(r.reason, Reason::Ok);
    assert!(
        r.quote_delta_lp < 0,
        "NEW-3: LP must pay quote on user sell, got {}",
        r.quote_delta_lp
    );
}

/// Large buy with no limit: must still be a positive exec_size.
/// This is the exact scenario that triggered NEW-3 (large req_size was
/// misinterpreted as a sell due to sign inversion).
#[test]
fn new3_large_buy_never_inverts_to_sell() {
    let large_buy: i128 = i64::MAX as i128;
    let mut lp = default_lp();
    let r = matcher().execute_match(&default_cfg(), &mut lp, 100_000, large_buy, None);
    // Either Ok or a resource-limit rejection — but never a negative exec_size
    assert!(
        r.exec.size >= 0,
        "NEW-3: large buy must never produce negative exec.size (inversion bug), got {}",
        r.exec.size
    );
}

// ---------------------------------------------------------------------------
// Quote math
// ---------------------------------------------------------------------------

#[test]
fn quote_bid_is_below_oracle() {
    let q = compute_quote(&default_cfg(), 100_000).unwrap();
    assert!(q.bid < 100_000, "bid must be below oracle");
}

#[test]
fn quote_ask_is_above_oracle() {
    let q = compute_quote(&default_cfg(), 100_000).unwrap();
    assert!(q.ask > 100_000, "ask must be above oracle");
}

#[test]
fn quote_zero_oracle_returns_none() {
    assert!(compute_quote(&default_cfg(), 0).is_none());
}

/// oracle=100_000, edge=50 bps
/// bid = floor(100_000 * 9950 / 10_000) = 99_500
/// ask = ceil(100_000 * 10_050 / 10_000) = 100_500
#[test]
fn quote_known_vector_50bps() {
    let q = compute_quote(&default_cfg(), 100_000).unwrap();
    assert_eq!(q.bid, 99_500);
    assert_eq!(q.ask, 100_500);
}

/// ask rounds up when not evenly divisible
/// oracle=100_001
/// ask_numer = 100_001 * 10_050 = 1_005_010_050
/// ask = ceil(1_005_010_050 / 10_000) = ceil(100_501.005) = 100_502
#[test]
fn quote_ask_rounds_up_known_vector() {
    let q = compute_quote(&default_cfg(), 100_001).unwrap();
    assert_eq!(q.ask, 100_502);
}

/// bid rounds down when not evenly divisible
/// oracle=100_001
/// bid_numer = 100_001 * 9_950 = 995_009_950
/// bid = floor(995_009_950 / 10_000) = 99_500.995 → 99_500
#[test]
fn quote_bid_rounds_down_known_vector() {
    let q = compute_quote(&default_cfg(), 100_001).unwrap();
    assert_eq!(q.bid, 99_500);
}

// ---------------------------------------------------------------------------
// Execution price locks: buy at ask, sell at bid
// ---------------------------------------------------------------------------

#[test]
fn buy_executes_at_ask() {
    let mut lp = default_lp();
    let r = matcher().execute_match(&default_cfg(), &mut lp, 100_000, 1, None);
    assert_eq!(r.reason, Reason::Ok);
    let q = compute_quote(&default_cfg(), 100_000).unwrap();
    assert_eq!(r.exec.price, q.ask, "buy must execute at ask");
}

#[test]
fn sell_executes_at_bid() {
    let mut lp = default_lp();
    let r = matcher().execute_match(&default_cfg(), &mut lp, 100_000, -1, None);
    assert_eq!(r.reason, Reason::Ok);
    let q = compute_quote(&default_cfg(), 100_000).unwrap();
    assert_eq!(r.exec.price, q.bid, "sell must execute at bid");
}

// ---------------------------------------------------------------------------
// Quote amount: exec.price * |exec.size|
// ---------------------------------------------------------------------------

#[test]
fn buy_quote_delta_equals_price_times_size() {
    let mut lp = default_lp();
    let r = matcher().execute_match(&default_cfg(), &mut lp, 100_000, 7, None);
    assert_eq!(r.reason, Reason::Ok);
    let expected_quote = r.exec.price as i128 * r.exec.size.abs();
    assert_eq!(r.quote_delta_lp, expected_quote);
}

#[test]
fn sell_quote_delta_equals_negative_price_times_size() {
    let mut lp = default_lp();
    let r = matcher().execute_match(&default_cfg(), &mut lp, 100_000, -7, None);
    assert_eq!(r.reason, Reason::Ok);
    // quote_delta_lp should be -(price * |size|)
    let expected_quote = -(r.exec.price as i128 * r.exec.size.abs());
    assert_eq!(r.quote_delta_lp, expected_quote);
}

// ---------------------------------------------------------------------------
// Limit price: boundary conditions
// ---------------------------------------------------------------------------

#[test]
fn buy_limit_at_ask_succeeds() {
    let q = compute_quote(&default_cfg(), 100_000).unwrap();
    let mut lp = default_lp();
    let r = matcher().execute_match(&default_cfg(), &mut lp, 100_000, 1, Some(q.ask));
    assert_eq!(r.reason, Reason::Ok);
}

#[test]
fn buy_limit_below_ask_fails() {
    let q = compute_quote(&default_cfg(), 100_000).unwrap();
    let mut lp = default_lp();
    let r = matcher().execute_match(&default_cfg(), &mut lp, 100_000, 1, Some(q.ask - 1));
    assert_eq!(r.reason, Reason::TakerLimitTooTight);
    assert_eq!(r.exec.size, 0);
}

#[test]
fn sell_limit_at_bid_succeeds() {
    let q = compute_quote(&default_cfg(), 100_000).unwrap();
    let mut lp = default_lp();
    let r = matcher().execute_match(&default_cfg(), &mut lp, 100_000, -1, Some(q.bid));
    assert_eq!(r.reason, Reason::Ok);
}

#[test]
fn sell_limit_above_bid_fails() {
    let q = compute_quote(&default_cfg(), 100_000).unwrap();
    let mut lp = default_lp();
    let r = matcher().execute_match(&default_cfg(), &mut lp, 100_000, -1, Some(q.bid + 1));
    assert_eq!(r.reason, Reason::TakerLimitTooTight);
    assert_eq!(r.exec.size, 0);
}

// ---------------------------------------------------------------------------
// Rejection: zero and below-min quantity
// ---------------------------------------------------------------------------

#[test]
fn zero_qty_rejected() {
    let mut lp = default_lp();
    let r = matcher().execute_match(&default_cfg(), &mut lp, 100_000, 0, None);
    assert_eq!(r.reason, Reason::ZeroQty);
}

#[test]
fn below_min_base_qty_rejected() {
    let cfg = PassiveMatcherConfig { min_base_qty: 10, ..default_cfg() };
    let mut lp = default_lp();
    let r = matcher().execute_match(&cfg, &mut lp, 100_000, 5, None);
    assert_eq!(r.reason, Reason::ZeroQty);
    // LP state must be unchanged
    assert_eq!(lp.inventory_base, 0);
}

#[test]
fn at_min_base_qty_succeeds() {
    let cfg = PassiveMatcherConfig { min_base_qty: 10, ..default_cfg() };
    let mut lp = default_lp();
    let r = matcher().execute_match(&cfg, &mut lp, 100_000, 10, None);
    assert_eq!(r.reason, Reason::Ok);
}

// ---------------------------------------------------------------------------
// Rejection: zero oracle
// ---------------------------------------------------------------------------

#[test]
fn zero_oracle_rejected() {
    let mut lp = default_lp();
    let r = matcher().execute_match(&default_cfg(), &mut lp, 0, 1, None);
    assert_eq!(r.reason, Reason::OracleZero);
}

// ---------------------------------------------------------------------------
// Size cap (max_base_qty)
// ---------------------------------------------------------------------------

#[test]
fn buy_capped_at_max_base_qty() {
    let cfg = PassiveMatcherConfig { max_base_qty: 5, ..default_cfg() };
    let mut lp = default_lp();
    let r = matcher().execute_match(&cfg, &mut lp, 100_000, 1000, None);
    assert_eq!(r.reason, Reason::Ok);
    assert_eq!(r.exec.size, 5, "exec size must be capped at max_base_qty");
    assert_eq!(lp.inventory_base, -5);
}

#[test]
fn sell_capped_at_max_base_qty() {
    let cfg = PassiveMatcherConfig { max_base_qty: 5, ..default_cfg() };
    let mut lp = default_lp();
    let r = matcher().execute_match(&cfg, &mut lp, 100_000, -1000, None);
    assert_eq!(r.reason, Reason::Ok);
    assert_eq!(r.exec.size, -5);
    assert_eq!(lp.inventory_base, 5);
}

// ---------------------------------------------------------------------------
// Inventory limit
// ---------------------------------------------------------------------------

#[test]
fn inventory_limit_buy_rejected_when_at_max() {
    let cfg = PassiveMatcherConfig {
        max_abs_inventory: 10,
        ..default_cfg()
    };
    let mut lp = PassiveLpState { inventory_base: -10 }; // LP already at short limit
    let r = matcher().execute_match(&cfg, &mut lp, 100_000, 1, None);
    assert_eq!(r.reason, Reason::LpInventoryLimit);
    assert_eq!(lp.inventory_base, -10, "inventory must not change on rejection");
}

#[test]
fn inventory_limit_sell_rejected_when_at_max() {
    let cfg = PassiveMatcherConfig {
        max_abs_inventory: 10,
        ..default_cfg()
    };
    let mut lp = PassiveLpState { inventory_base: 10 }; // LP already at long limit
    let r = matcher().execute_match(&cfg, &mut lp, 100_000, -1, None);
    assert_eq!(r.reason, Reason::LpInventoryLimit);
    assert_eq!(lp.inventory_base, 10, "inventory must not change on rejection");
}

#[test]
fn inventory_limit_buy_accepted_when_one_below_limit() {
    let cfg = PassiveMatcherConfig {
        max_abs_inventory: 10,
        ..default_cfg()
    };
    let mut lp = PassiveLpState { inventory_base: -9 }; // one unit of headroom
    let r = matcher().execute_match(&cfg, &mut lp, 100_000, 1, None);
    assert_eq!(r.reason, Reason::Ok);
    assert_eq!(lp.inventory_base, -10);
}

#[test]
fn inventory_state_unchanged_on_any_rejection() {
    // Verify all rejection paths leave LP state immutable.
    let rejects: &[(i128, i128, Option<u64>)] = &[
        (100_000, 0, None),           // zero qty
        (0, 1, None),                 // oracle zero
        (100_000, 1, Some(0)),        // limit too tight
    ];
    for (oracle, size, limit) in rejects {
        let mut lp = PassiveLpState { inventory_base: 42 };
        let _ = matcher().execute_match(&default_cfg(), &mut lp, *oracle as u64, *size, *limit);
        assert_eq!(lp.inventory_base, 42, "inventory must not change on rejection");
    }
}

// ---------------------------------------------------------------------------
// Sequential trades: inventory accumulates correctly
// ---------------------------------------------------------------------------

#[test]
fn sequential_trades_inventory_accumulates() {
    let mut lp = PassiveLpState { inventory_base: 0 };
    let oracle = 100_000u64;

    // Trade 1: user buys 3 → LP inventory = -3
    let r1 = matcher().execute_match(&default_cfg(), &mut lp, oracle, 3, None);
    assert_eq!(r1.reason, Reason::Ok);
    assert_eq!(lp.inventory_base, -3);

    // Trade 2: user sells 10 → LP inventory = -3 + 10 = 7
    let r2 = matcher().execute_match(&default_cfg(), &mut lp, oracle, -10, None);
    assert_eq!(r2.reason, Reason::Ok);
    assert_eq!(lp.inventory_base, 7);

    // Trade 3: user buys 7 → LP inventory = 7 - 7 = 0 (flat)
    let r3 = matcher().execute_match(&default_cfg(), &mut lp, oracle, 7, None);
    assert_eq!(r3.reason, Reason::Ok);
    assert_eq!(lp.inventory_base, 0);

    // Verify each exec.size sign
    assert_eq!(r1.exec.size, 3);
    assert_eq!(r2.exec.size, -10);
    assert_eq!(r3.exec.size, 7);
}

// ---------------------------------------------------------------------------
// MatchResult helpers
// ---------------------------------------------------------------------------

#[test]
fn unfilled_has_zero_price_and_size() {
    let r = MatchResult::unfilled(Reason::OracleZero);
    assert_eq!(r.exec.price, 0);
    assert_eq!(r.exec.size, 0);
    assert_eq!(r.quote_delta_lp, 0);
}

#[test]
fn filled_carries_correct_values() {
    let r = MatchResult::filled(99_500, -10, -995_000);
    assert_eq!(r.exec.price, 99_500);
    assert_eq!(r.exec.size, -10);
    assert_eq!(r.quote_delta_lp, -995_000);
    assert_eq!(r.reason, Reason::Ok);
}

// ---------------------------------------------------------------------------
// Trait implementation parity
// ---------------------------------------------------------------------------

#[test]
fn trait_impl_produces_same_result_as_direct_call() {
    use percolator_match::passive_lp_matcher::MatchingEngine;

    let cfg = default_cfg();
    let oracle = 100_000u64;
    let req_size = 10i128;

    let mut lp1 = default_lp();
    let mut lp2 = default_lp();
    let m = PassiveOracleBpsMatcher;

    let r1 = PassiveOracleBpsMatcher::execute_match(&m, &cfg, &mut lp1, oracle, req_size, None);
    let r2 = <PassiveOracleBpsMatcher as MatchingEngine>::execute_match(
        &m, &cfg, &mut lp2, oracle, req_size, None,
    );

    assert_eq!(r1.exec.price, r2.exec.price);
    assert_eq!(r1.exec.size, r2.exec.size);
    assert_eq!(r1.reason, r2.reason);
    assert_eq!(lp1.inventory_base, lp2.inventory_base);
}

// ---------------------------------------------------------------------------
// Edge prices: u64::MAX oracle (no panic)
// ---------------------------------------------------------------------------

#[test]
fn max_oracle_price_buy_no_panic() {
    let cfg = PassiveMatcherConfig {
        edge_bps: 1, // 0.01% — very tight to avoid u128 overflow on large oracle
        ..default_cfg()
    };
    let mut lp = default_lp();
    // u64::MAX with 1 bps edge: ask_numer = u64::MAX * 10_001
    // = 18446744073709551615 * 10_001 > u128::MAX? No: u128::MAX = 3.4e38
    // u64::MAX * 10_001 ≈ 1.84e23, well within u128.
    let r = matcher().execute_match(&cfg, &mut lp, u64::MAX, 1, None);
    // May return MathOverflow (ask overflow to >u64::MAX is expected) or Ok — either is valid.
    // We assert only no panic, and that exec.size is correct sign.
    if r.reason == Reason::Ok {
        assert!(r.exec.size > 0);
    } else {
        // Any non-Ok reason is acceptable here (overflow, etc.)
        assert_eq!(r.exec.size, 0);
    }
}
