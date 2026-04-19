//! Account and instruction layout tests.
//!
//! These tests assert exact byte sizes and field offsets for every on-chain
//! structure. Any size change is a breaking ABI change (MATCHER_ABI_VERSION must bump).
//!
//! Offset values come from the struct comment in vamm.rs — we assert both the
//! documented offset and the real runtime offset so they can't drift apart.

use percolator_match::{
    MatcherCall, MatcherReturn,
    MATCHER_CALL_LEN, MATCHER_CONTEXT_LEN, MATCHER_RETURN_LEN,
    CTX_RETURN_OFFSET, CTX_VAMM_OFFSET, CTX_VAMM_LEN,
};
use percolator_match::vamm::{InitParams, MatcherCtx, INIT_CTX_LEN, MATCHER_MAGIC, MATCHER_VERSION};

// ---------------------------------------------------------------------------
// Documented constant values — lock them so they can't silently change
// ---------------------------------------------------------------------------

#[test]
fn ctx_return_offset_is_0() {
    assert_eq!(CTX_RETURN_OFFSET, 0);
}

#[test]
fn matcher_return_len_is_64() {
    assert_eq!(MATCHER_RETURN_LEN, 64);
}

#[test]
fn ctx_vamm_offset_is_64() {
    // The first 64 bytes of the context account hold the MatcherReturn.
    // vAMM state starts after that.
    assert_eq!(CTX_VAMM_OFFSET, 64);
}

#[test]
fn ctx_vamm_len_is_256() {
    assert_eq!(CTX_VAMM_LEN, 256);
}

#[test]
fn matcher_context_len_is_320() {
    // Total context account: 64 (return) + 256 (MatcherCtx) = 320
    assert_eq!(MATCHER_CONTEXT_LEN, 320);
    assert_eq!(CTX_RETURN_OFFSET + MATCHER_RETURN_LEN + CTX_VAMM_LEN, 320);
}

#[test]
fn matcher_call_len_is_67() {
    // tag(1) + req_id(8) + lp_idx(2) + lp_account_id(8) + oracle_price_e6(8) +
    // req_size(16) + padding(24) = 67
    assert_eq!(MATCHER_CALL_LEN, 67);
}

#[test]
fn init_ctx_len_is_78() {
    // tag(1) + kind(1) + trading_fee_bps(4) + base_spread_bps(4) + max_total_bps(4) +
    // impact_k_bps(4) + liquidity_notional_e6(16) + max_fill_abs(16) +
    // max_inventory_abs(16) + fee_to_insurance_bps(2) + skew_spread_mult_bps(2) +
    // lp_account_id(8) = 78
    assert_eq!(INIT_CTX_LEN, 78);
}

// ---------------------------------------------------------------------------
// MatcherReturn size
// ---------------------------------------------------------------------------

#[test]
fn matcher_return_struct_size() {
    // Must be exactly 64 bytes so write_to fills the first 64 bytes of the
    // context account (CTX_RETURN_OFFSET..CTX_VAMM_OFFSET).
    assert_eq!(core::mem::size_of::<MatcherReturn>(), MATCHER_RETURN_LEN);
}

// ---------------------------------------------------------------------------
// MatcherReturn serialization: every field at documented byte offset
// ---------------------------------------------------------------------------

#[test]
fn matcher_return_field_offsets_via_write_to() {
    let ret = MatcherReturn {
        abi_version: 0x0000_0002,
        flags: 0x0000_0001,
        exec_price_e6: 0x0102_0304_0506_0708,
        exec_size: 0x0102_0304_0506_0708_090A_0B0C_0D0E_0F10_i128,
        req_id: 0xAA_BB_CC_DD_EE_FF_00_11,
        lp_account_id: 0x11_22_33_44_55_66_77_88,
        oracle_price_e6: 0xCA_FE_BA_BE_DE_AD_BE_EF,
        reserved: 0,
    };
    let mut buf = [0u8; 64];
    ret.write_to(&mut buf).unwrap();

    // abi_version at 0..4
    assert_eq!(u32::from_le_bytes(buf[0..4].try_into().unwrap()), ret.abi_version);
    // flags at 4..8
    assert_eq!(u32::from_le_bytes(buf[4..8].try_into().unwrap()), ret.flags);
    // exec_price_e6 at 8..16
    assert_eq!(u64::from_le_bytes(buf[8..16].try_into().unwrap()), ret.exec_price_e6);
    // exec_size at 16..32
    assert_eq!(i128::from_le_bytes(buf[16..32].try_into().unwrap()), ret.exec_size);
    // req_id at 32..40
    assert_eq!(u64::from_le_bytes(buf[32..40].try_into().unwrap()), ret.req_id);
    // lp_account_id at 40..48
    assert_eq!(u64::from_le_bytes(buf[40..48].try_into().unwrap()), ret.lp_account_id);
    // oracle_price_e6 at 48..56
    assert_eq!(u64::from_le_bytes(buf[48..56].try_into().unwrap()), ret.oracle_price_e6);
    // reserved at 56..64
    assert_eq!(u64::from_le_bytes(buf[56..64].try_into().unwrap()), 0u64);
}

// ---------------------------------------------------------------------------
// MatcherCall parse: field offsets in instruction data
// ---------------------------------------------------------------------------

#[test]
fn matcher_call_field_offsets() {
    // Build a 67-byte buffer with known values at each field's documented offset.
    let mut data = [0u8; 67];
    data[0] = 0u8; // tag
    let req_id: u64 = 0xDEAD_BEEF_CAFE_1234;
    let lp_idx: u16 = 7;
    let lp_account_id: u64 = 0x1111_2222_3333_4444;
    let oracle_price_e6: u64 = 100_000_000;
    let req_size: i128 = -500_000;

    data[1..9].copy_from_slice(&req_id.to_le_bytes());
    data[9..11].copy_from_slice(&lp_idx.to_le_bytes());
    data[11..19].copy_from_slice(&lp_account_id.to_le_bytes());
    data[19..27].copy_from_slice(&oracle_price_e6.to_le_bytes());
    data[27..43].copy_from_slice(&req_size.to_le_bytes());
    // bytes 43..67 remain zero (padding)

    let call = MatcherCall::parse(&data).unwrap();
    assert_eq!(call.req_id, req_id);
    assert_eq!(call.lp_idx, lp_idx);
    assert_eq!(call.lp_account_id, lp_account_id);
    assert_eq!(call.oracle_price_e6, oracle_price_e6);
    assert_eq!(call.req_size, req_size);
}

#[test]
fn matcher_call_parse_rejects_nonzero_padding() {
    let mut data = [0u8; 67];
    // Set non-zero at byte 43 (start of 24-byte reserved section)
    data[43] = 0xFF;
    let result = MatcherCall::parse(&data);
    assert!(result.is_err(), "non-zero padding must be rejected");
}

#[test]
fn matcher_call_parse_rejects_wrong_tag() {
    let mut data = [0u8; 67];
    data[0] = 2; // MATCHER_INIT_VAMM_TAG — not a call tag
    let result = MatcherCall::parse(&data);
    assert!(result.is_err(), "wrong tag must be rejected");
}

// ---------------------------------------------------------------------------
// MatcherCtx layout (256 bytes at offset 64)
// ---------------------------------------------------------------------------

#[test]
fn matcher_ctx_size_is_256() {
    assert_eq!(core::mem::size_of::<MatcherCtx>(), CTX_VAMM_LEN);
    assert_eq!(core::mem::size_of::<MatcherCtx>(), 256);
}

#[test]
fn matcher_ctx_magic_constant() {
    // "PERCMATC" as LE u64 — the SDK asserts VAMM_MAGIC == 0x5045524343_...
    // We pin the exact value so it can't drift.
    assert_eq!(MATCHER_MAGIC, 0x5045_5243_4d41_5443u64);
}

#[test]
fn matcher_ctx_version_constant() {
    assert_eq!(MATCHER_VERSION, 4u32);
}

/// Assert field offsets via manual write_to/read_from roundtrip with sentinel values.
#[test]
fn matcher_ctx_field_offsets_via_serialization() {
    let ctx = MatcherCtx {
        magic: MATCHER_MAGIC,
        version: MATCHER_VERSION,
        kind: 1,           // vAMM
        _pad0: [0u8; 3],
        lp_pda: [0xABu8; 32],
        trading_fee_bps: 0x0A0B_0C0D,
        base_spread_bps: 0x1A1B_1C1D,
        max_total_bps: 0x2A2B_2C2D,
        impact_k_bps: 0x3A3B_3C3D,
        liquidity_notional_e6: 0xDEAD_BEEF_CAFE_1234_5678_9ABC_DEF0_0123u128,
        max_fill_abs: 0x1111_2222_3333_4444_5555_6666_7777_8888u128,
        inventory_base: -987654321i128,
        last_oracle_price_e6: 0xAAAA_BBBB_CCCC_DDDDu64,
        last_exec_price_e6: 0x1234_5678_9ABC_DEF0u64,
        max_inventory_abs: i128::MAX as u128,
        insurance_accrued_e6: 0x0102_0304_0506_0708u64,
        fee_to_insurance_bps: 0x0FFF,
        skew_spread_mult_bps: 0x0EEE,
        _new_pad: [0u8; 4],
        lp_account_id: 0xCAFE_BABE_1234_5678u64,
        _reserved: [0u8; 88],
    };

    let mut buf = [0u8; 256];
    ctx.write_to(&mut buf).unwrap();

    // magic at 0..8
    assert_eq!(u64::from_le_bytes(buf[0..8].try_into().unwrap()), MATCHER_MAGIC);
    // version at 8..12
    assert_eq!(u32::from_le_bytes(buf[8..12].try_into().unwrap()), MATCHER_VERSION);
    // kind at 12
    assert_eq!(buf[12], 1u8);
    // pad0 at 13..16 — must be zeros
    assert_eq!(&buf[13..16], &[0u8; 3]);
    // lp_pda at 16..48
    assert_eq!(&buf[16..48], &[0xABu8; 32]);
    // trading_fee_bps at 48..52
    assert_eq!(u32::from_le_bytes(buf[48..52].try_into().unwrap()), ctx.trading_fee_bps);
    // base_spread_bps at 52..56
    assert_eq!(u32::from_le_bytes(buf[52..56].try_into().unwrap()), ctx.base_spread_bps);
    // max_total_bps at 56..60
    assert_eq!(u32::from_le_bytes(buf[56..60].try_into().unwrap()), ctx.max_total_bps);
    // impact_k_bps at 60..64
    assert_eq!(u32::from_le_bytes(buf[60..64].try_into().unwrap()), ctx.impact_k_bps);
    // liquidity_notional_e6 at 64..80
    assert_eq!(u128::from_le_bytes(buf[64..80].try_into().unwrap()), ctx.liquidity_notional_e6);
    // max_fill_abs at 80..96
    assert_eq!(u128::from_le_bytes(buf[80..96].try_into().unwrap()), ctx.max_fill_abs);
    // inventory_base at 96..112
    assert_eq!(i128::from_le_bytes(buf[96..112].try_into().unwrap()), ctx.inventory_base);
    // last_oracle_price_e6 at 112..120
    assert_eq!(u64::from_le_bytes(buf[112..120].try_into().unwrap()), ctx.last_oracle_price_e6);
    // last_exec_price_e6 at 120..128
    assert_eq!(u64::from_le_bytes(buf[120..128].try_into().unwrap()), ctx.last_exec_price_e6);
    // max_inventory_abs at 128..144
    assert_eq!(u128::from_le_bytes(buf[128..144].try_into().unwrap()), ctx.max_inventory_abs);
    // insurance_accrued_e6 at 144..152
    assert_eq!(u64::from_le_bytes(buf[144..152].try_into().unwrap()), ctx.insurance_accrued_e6);
    // fee_to_insurance_bps at 152..154
    assert_eq!(u16::from_le_bytes(buf[152..154].try_into().unwrap()), ctx.fee_to_insurance_bps);
    // skew_spread_mult_bps at 154..156
    assert_eq!(u16::from_le_bytes(buf[154..156].try_into().unwrap()), ctx.skew_spread_mult_bps);
    // _new_pad at 156..160 — zeros
    assert_eq!(&buf[156..160], &[0u8; 4]);
    // lp_account_id at 160..168
    assert_eq!(u64::from_le_bytes(buf[160..168].try_into().unwrap()), ctx.lp_account_id);
    // _reserved at 168..256 — zeros
    assert_eq!(&buf[168..256], &[0u8; 88]);
}

// ---------------------------------------------------------------------------
// InitParams encode/parse — field offsets
// ---------------------------------------------------------------------------

#[test]
fn init_params_field_offsets() {
    let params = InitParams {
        kind: 1,
        trading_fee_bps: 0x0102_0304,
        base_spread_bps: 0x0506_0708,
        max_total_bps: 0x090A_0B0C,
        impact_k_bps: 0x0D0E_0F10,
        liquidity_notional_e6: 0xDEAD_BEEF_CAFE_0000_1111_2222_3333_4444u128,
        max_fill_abs: 0xAAAA_BBBB_CCCC_DDDD_EEEE_FFFF_0000_1111u128,
        max_inventory_abs: 0x1234_5678_9ABC_DEF0_0FED_CBA9_8765_4321u128,
        fee_to_insurance_bps: 0x1234,
        skew_spread_mult_bps: 0x5678,
        lp_account_id: 0xCAFE_BABE_DEAD_BEEFu64,
    };

    let buf = params.encode();
    assert_eq!(buf.len(), INIT_CTX_LEN);

    // tag at 0
    assert_eq!(buf[0], 2u8); // MATCHER_INIT_VAMM_TAG
    // kind at 1
    assert_eq!(buf[1], params.kind);
    // trading_fee_bps at 2..6
    assert_eq!(u32::from_le_bytes(buf[2..6].try_into().unwrap()), params.trading_fee_bps);
    // base_spread_bps at 6..10
    assert_eq!(u32::from_le_bytes(buf[6..10].try_into().unwrap()), params.base_spread_bps);
    // max_total_bps at 10..14
    assert_eq!(u32::from_le_bytes(buf[10..14].try_into().unwrap()), params.max_total_bps);
    // impact_k_bps at 14..18
    assert_eq!(u32::from_le_bytes(buf[14..18].try_into().unwrap()), params.impact_k_bps);
    // liquidity_notional_e6 at 18..34
    assert_eq!(u128::from_le_bytes(buf[18..34].try_into().unwrap()), params.liquidity_notional_e6);
    // max_fill_abs at 34..50
    assert_eq!(u128::from_le_bytes(buf[34..50].try_into().unwrap()), params.max_fill_abs);
    // max_inventory_abs at 50..66
    assert_eq!(u128::from_le_bytes(buf[50..66].try_into().unwrap()), params.max_inventory_abs);
    // fee_to_insurance_bps at 66..68
    assert_eq!(u16::from_le_bytes(buf[66..68].try_into().unwrap()), params.fee_to_insurance_bps);
    // skew_spread_mult_bps at 68..70
    assert_eq!(u16::from_le_bytes(buf[68..70].try_into().unwrap()), params.skew_spread_mult_bps);
    // lp_account_id at 70..78
    assert_eq!(u64::from_le_bytes(buf[70..78].try_into().unwrap()), params.lp_account_id);
}

// ---------------------------------------------------------------------------
// Bug-flag: SDK lp_account_id gap
// ---------------------------------------------------------------------------

/// INIT_CTX_LEN is 78 bytes. percolator-prog reads lp_account_id from the engine's
/// generation table and appends it at offset 70..78 when building the CPI payload.
/// This test pins the constant so any accidental resize is caught immediately.
#[test]
fn init_ctx_len_rust_side_includes_lp_account_id() {
    // tag(1) + kind(1) + fees(4+4+4+4) + u128s(16+16+16) + bps(2+2) + lp_account_id(8) = 78
    assert_eq!(INIT_CTX_LEN, 78, "Rust INIT_CTX_LEN must be 78 (includes lp_account_id)");
}
