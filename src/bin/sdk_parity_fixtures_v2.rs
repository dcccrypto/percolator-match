//! P2 matcher v2 ABI fixture for percolator-sdk (additive).
//!
//! Kept separate from `sdk_parity_fixtures` on purpose: that binary's output is compared
//! byte-for-byte against `percolator-sdk/specs/matcher-parity.json` in CI, and the SDK has
//! not adopted v2 yet. When it does, fold this into the main fixture in the same PR as the
//! SDK spec update.
//! Run: cargo run --bin sdk_parity_fixtures_v2

use percolator_match::v2::{
    self, CallExt, V2Block, V2Config, CALL_EXT_LEN, CALL_EXT_OFFSET, ERR_ASSET_MISMATCH,
    ERR_MARK_SLOT_IN_FUTURE, ERR_OWNER_PROOF_MISMATCH, ERR_STALE_MARK, V2_BLOCK_CTX_OFFSET,
    V2_BLOCK_LEN,
};
use percolator_match::vamm::{
    SetParams, CONFIGURE_AUTH_LP_PDA, CONFIGURE_AUTH_OWNER_PROOF, CONFIGURE_HEADER_LP_PDA_LEN,
    CONFIGURE_HEADER_OWNER_PROOF_LEN, CONFIGURE_OP_BACKING_FEE_CAP, CONFIGURE_OP_SET_PARAMS,
    MATCHER_CONFIGURE_TAG, SET_PARAMS_LEN,
};
use percolator_match::{FLAG_REQUESTED_FEE_MASK, FLAG_REQUESTED_FEE_SHIFT, REQUESTED_FEE_BPS_MAX};
use serde_json::json;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let ext = CallExt {
        headroom_q: Some(0x0102_0304_0506_0708),
        mark_slot: Some(0x1112_1314_1516_1718),
        accepts_fee_request: true,
        taker_reducing: true,
        exec_band_bps: Some(500),
    };
    let cfg = v2::default_config_for_kind2(10, 50, 200, 50, 4_000);
    let sp = SetParams {
        kind: 2,
        trading_fee_bps: 0,
        base_spread_bps: 50,
        max_total_bps: 200,
        impact_k_bps: 10_000,
        liquidity_notional_e6: 1_000_000_000,
        max_fill_abs: 1_000,
        max_inventory_abs: 4_000,
        fee_to_insurance_bps: 0,
        skew_spread_mult_bps: 50,
        enable_v2: true,
        v2: cfg,
    };
    let out = json!({
        "call_ext": {
            "offset_in_tag0_call": CALL_EXT_OFFSET,
            "len": CALL_EXT_LEN,
            "version": v2::CALL_EXT_VERSION_V1,
            "flags": {
                "HEADROOM": v2::EXT_FLAG_HEADROOM,
                "MARK_SLOT": v2::EXT_FLAG_MARK_SLOT,
                "ACCEPTS_FEE_REQUEST": v2::EXT_FLAG_ACCEPTS_FEE_REQUEST,
                "TAKER_REDUCING": v2::EXT_FLAG_TAKER_REDUCING,
                "EXEC_BAND": v2::EXT_FLAG_EXEC_BAND,
            },
            "field_offsets": { "ext_version": 0, "ext_flags": 1, "exec_band_bps": 2,
                               "mark_slot": 4, "lp_headroom_q": 12, "reserved": 20 },
            "example_hex": hex(&ext.encode()),
            "batch_trailer": "tag 3 length 18 + 26*n + 24*n: one ext per leg after all legs",
        },
        "return_flags": {
            "REQUESTED_FEE_SHIFT": FLAG_REQUESTED_FEE_SHIFT,
            "REQUESTED_FEE_MASK": FLAG_REQUESTED_FEE_MASK,
            "REQUESTED_FEE_BPS_MAX": REQUESTED_FEE_BPS_MAX,
        },
        "ctx_v2_block": {
            "ctx_offset": V2_BLOCK_CTX_OFFSET,
            "account_offset": 64 + V2_BLOCK_CTX_OFFSET,
            "len": V2_BLOCK_LEN,
            "marker_value": v2::V2_BLOCK_VERSION,
            "default_kind2_example_hex": hex(&V2Block::fresh(cfg).encode()),
        },
        "configure_tag5": {
            "tag": MATCHER_CONFIGURE_TAG,
            "auth_lp_pda": CONFIGURE_AUTH_LP_PDA,
            "auth_owner_proof": CONFIGURE_AUTH_OWNER_PROOF,
            "header_len_lp_pda": CONFIGURE_HEADER_LP_PDA_LEN,
            "header_len_owner_proof": CONFIGURE_HEADER_OWNER_PROOF_LEN,
            "op_backing_fee_cap": CONFIGURE_OP_BACKING_FEE_CAP,
            "op_set_params": CONFIGURE_OP_SET_PARAMS,
            "set_params_len": SET_PARAMS_LEN,
            "set_params_example_hex": hex(&sp.encode()),
            "owner_proof_seeds": ["matcher", "market", "lp_portfolio", "lp_owner(signer)",
                                  "matcher_program_id", "matcher_ctx", "[bump]"],
        },
        "errors": {
            "ERR_STALE_MARK": ERR_STALE_MARK,
            "ERR_MARK_SLOT_IN_FUTURE": ERR_MARK_SLOT_IN_FUTURE,
            "ERR_ASSET_MISMATCH": ERR_ASSET_MISMATCH,
            "ERR_OWNER_PROOF_MISMATCH": ERR_OWNER_PROOF_MISMATCH,
        },
        "kind_adaptive": 2,
        "default_config_kind2_for_fee10_base50_max200_skew50_inv4000": format!("{:?}", V2Config { ..cfg }),
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}
