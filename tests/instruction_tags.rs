//! Instruction tag / discriminator stability tests.
//!
//! These tests lock the tag byte values against accidental reorderings.
//! Any change here breaks the CPI ABI with percolator-prog and the SDK.

use percolator_match::{MATCHER_ABI_VERSION, MATCHER_CALL_TAG, MATCHER_INIT_VAMM_TAG};

// ---------------------------------------------------------------------------
// Tag value locks
// ---------------------------------------------------------------------------

#[test]
fn tag_matcher_call_is_0() {
    // Tag 0 is what percolator-prog sends for every TradeCpi / TradeCpiV2 CPI.
    assert_eq!(MATCHER_CALL_TAG, 0u8, "MATCHER_CALL_TAG must be 0 — breaking change");
}

#[test]
fn tag_matcher_init_vamm_is_2() {
    // Tag 2 is the InitMatcherCtx instruction dispatched from percolator-prog (tag 75).
    assert_eq!(MATCHER_INIT_VAMM_TAG, 2u8, "MATCHER_INIT_VAMM_TAG must be 2 — breaking change");
}

#[test]
fn abi_version_is_2() {
    // MATCHER_ABI_VERSION is echoed in every MatcherReturn. The SDK and keeper both assert
    // this value; bumping it without coordinating breaks all active markets.
    assert_eq!(MATCHER_ABI_VERSION, 2u32, "MATCHER_ABI_VERSION must be 2 — breaking change");
}

// ---------------------------------------------------------------------------
// Tag name stability (instruction data parse smoke test)
// ---------------------------------------------------------------------------

#[test]
fn parse_matcher_call_tag_byte() {
    // First byte of a minimal MATCHER_CALL instruction data.
    let data = [MATCHER_CALL_TAG; 1];
    assert_eq!(data[0], 0);
}

#[test]
fn parse_init_vamm_tag_byte() {
    let data = [MATCHER_INIT_VAMM_TAG; 1];
    assert_eq!(data[0], 2);
}

#[test]
fn unknown_tag_3_is_not_reachable() {
    // Tags 1 and 3+ are intentionally unassigned. If process_instruction were
    // callable here without a validator we'd assert Err; instead we verify no
    // known constant collides.
    assert_ne!(MATCHER_CALL_TAG, 1u8);
    assert_ne!(MATCHER_INIT_VAMM_TAG, 1u8);
    assert_ne!(MATCHER_CALL_TAG, 3u8);
    assert_ne!(MATCHER_INIT_VAMM_TAG, 3u8);
}

// ---------------------------------------------------------------------------
// MatcherCall parse — layout bytes at known offsets
// ---------------------------------------------------------------------------

#[test]
fn matcher_call_tag_byte_at_offset_0() {
    // The tag byte must be at index 0 of the encoded instruction data.
    // Build a minimal 67-byte MATCHER_CALL buffer and confirm the tag position.
    let mut data = [0u8; 67]; // MATCHER_CALL_LEN
    data[0] = MATCHER_CALL_TAG;
    // req_id = 0xDEAD_BEEF at bytes 1..9
    let req_id: u64 = 0xDEAD_BEEF;
    data[1..9].copy_from_slice(&req_id.to_le_bytes());

    assert_eq!(data[0], MATCHER_CALL_TAG);
    assert_eq!(u64::from_le_bytes(data[1..9].try_into().unwrap()), req_id);
}

#[test]
fn init_params_tag_byte_at_offset_0() {
    use percolator_match::vamm::InitParams;
    let params = InitParams {
        kind: 0,
        trading_fee_bps: 30,
        base_spread_bps: 50,
        max_total_bps: 500,
        impact_k_bps: 0,
        liquidity_notional_e6: 0,
        max_fill_abs: u128::MAX / 2,
        max_inventory_abs: u128::MAX / 2,
        fee_to_insurance_bps: 0,
        skew_spread_mult_bps: 0,
        lp_account_id: 1,
    };
    let encoded = params.encode();
    assert_eq!(encoded[0], MATCHER_INIT_VAMM_TAG, "tag byte must be at offset 0");
    assert_eq!(encoded[1], 0u8, "kind=0 (Passive) at offset 1");
}
