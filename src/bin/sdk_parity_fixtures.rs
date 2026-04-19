//! SDK parity fixture binary for percolator-match.
//!
//! Emits JSON consumed by ~/percolator-sdk/test/parity-fixtures.test.ts.
//! Run: cargo run --bin sdk_parity_fixtures
//! Redirect to: percolator-sdk/specs/matcher-parity.json
//!
//! Mirrors the pattern in percolator-prog, percolator-stake, and percolator-nft.

use percolator_match::{
    CTX_RETURN_OFFSET, CTX_VAMM_LEN, CTX_VAMM_OFFSET, MATCHER_ABI_VERSION, MATCHER_CALL_LEN,
    MATCHER_CALL_TAG, MATCHER_CONTEXT_LEN, MATCHER_INIT_VAMM_TAG, MATCHER_RETURN_LEN,
    FLAG_VALID, FLAG_PARTIAL_OK, FLAG_REJECTED,
};
use percolator_match::vamm::{
    INIT_CTX_LEN, MATCHER_MAGIC, MATCHER_VERSION, MatcherCtx, MatcherKind,
};
use serde_json::json;

fn main() {
    // Emit field offsets from the documented MatcherCtx layout (vamm.rs)
    // These values must match what the SDK reads when parsing the context account.
    let ctx_field_offsets = json!({
        "magic":                    0,
        "version":                  8,
        "kind":                     12,
        "_pad0":                    13,
        "lp_pda":                   16,
        "trading_fee_bps":          48,
        "base_spread_bps":          52,
        "max_total_bps":            56,
        "impact_k_bps":             60,
        "liquidity_notional_e6":    64,
        "max_fill_abs":             80,
        "inventory_base":           96,
        "last_oracle_price_e6":     112,
        "last_exec_price_e6":       120,
        "max_inventory_abs":        128,
        "insurance_accrued_e6":     144,
        "fee_to_insurance_bps":     152,
        "skew_spread_mult_bps":     154,
        "_new_pad":                 156,
        "lp_account_id":            160,
        "_reserved":                168,
    });

    // MatcherReturn field offsets (written at CTX_RETURN_OFFSET in context account)
    let return_field_offsets = json!({
        "abi_version":      0,
        "flags":            4,
        "exec_price_e6":    8,
        "exec_size":        16,
        "req_id":           32,
        "lp_account_id":    40,
        "oracle_price_e6":  48,
        "reserved":         56,
    });

    // MatcherCall instruction data field offsets
    let call_field_offsets = json!({
        "tag":              0,
        "req_id":           1,
        "lp_idx":           9,
        "lp_account_id":    11,
        "oracle_price_e6":  19,
        "req_size":         27,
        "_pad":             43,  // 24 bytes must be zero
    });

    // InitParams instruction data field offsets (tag=2 instruction)
    let init_field_offsets = json!({
        "tag":                      0,
        "kind":                     1,
        "trading_fee_bps":          2,
        "base_spread_bps":          6,
        "max_total_bps":            10,
        "impact_k_bps":             14,
        "liquidity_notional_e6":    18,
        "max_fill_abs":             34,
        "max_inventory_abs":        50,
        "fee_to_insurance_bps":     66,
        "skew_spread_mult_bps":     68,
        "lp_account_id":            70,
    });

    let tags = [
        ("MatcherCall",     MATCHER_CALL_TAG as u32),
        ("InitMatcherCtx",  MATCHER_INIT_VAMM_TAG as u32),
    ];

    let flags = json!({
        "FLAG_VALID":       FLAG_VALID,
        "FLAG_PARTIAL_OK":  FLAG_PARTIAL_OK,
        "FLAG_REJECTED":    FLAG_REJECTED,
    });

    let sizes = json!({
        "MATCHER_RETURN_LEN":   MATCHER_RETURN_LEN,
        "MATCHER_CALL_LEN":     MATCHER_CALL_LEN,
        "MATCHER_CONTEXT_LEN":  MATCHER_CONTEXT_LEN,
        "CTX_RETURN_OFFSET":    CTX_RETURN_OFFSET,
        "CTX_VAMM_OFFSET":      CTX_VAMM_OFFSET,
        "CTX_VAMM_LEN":         CTX_VAMM_LEN,
        "INIT_CTX_LEN":         INIT_CTX_LEN,
        // Rust struct size — must equal CTX_VAMM_LEN
        "MatcherCtx_size":      std::mem::size_of::<MatcherCtx>(),
    });

    let constants = json!({
        "MATCHER_ABI_VERSION":  MATCHER_ABI_VERSION,
        "MATCHER_VERSION":      MATCHER_VERSION,
        // MATCHER_MAGIC as hex string — matches SDK VAMM_MAGIC = 0x5045524343_...
        "MATCHER_MAGIC_hex":    format!("{:#018x}", MATCHER_MAGIC),
        "MATCHER_KIND_PASSIVE": MatcherKind::Passive as u8,
        "MATCHER_KIND_VAMM":    MatcherKind::Vamm as u8,
    });

    // Self-check: emit compile-time assertions as boolean — these should all be true.
    // If any is false the fixture itself is corrupt.
    let self_checks = json!({
        "matcher_ctx_size_eq_ctx_vamm_len":      std::mem::size_of::<MatcherCtx>() == CTX_VAMM_LEN,
        "return_offset_plus_return_len_eq_vamm_offset": CTX_RETURN_OFFSET + MATCHER_RETURN_LEN == CTX_VAMM_OFFSET,
        "vamm_offset_plus_vamm_len_eq_context_len": CTX_VAMM_OFFSET + CTX_VAMM_LEN == MATCHER_CONTEXT_LEN,
        "init_ctx_len_eq_78":                    INIT_CTX_LEN == 78,
        "matcher_call_len_eq_67":                MATCHER_CALL_LEN == 67,
    });

    let payload = json!({
        "program": "percolator-match",
        "tags": tags
            .into_iter()
            .map(|(name, tag)| json!({ "name": name, "tag": tag }))
            .collect::<Vec<_>>(),
        "flags": flags,
        "sizes": sizes,
        "constants": constants,
        "ctx_field_offsets": ctx_field_offsets,
        "return_field_offsets": return_field_offsets,
        "call_field_offsets": call_field_offsets,
        "init_field_offsets": init_field_offsets,
        "self_checks": self_checks,
    });

    println!("{}", serde_json::to_string_pretty(&payload).unwrap());
}
