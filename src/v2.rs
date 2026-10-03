//! Matcher v2 (P2): adaptive fee, size-based (constant-product) impact, skew surcharge /
//! thin-side rebate, stale-mark refusal and wrapper-supplied LP headroom.
//!
//! Compatibility contract
//! ----------------------
//! * The `MatcherCtx` struct layout is UNCHANGED. Everything v2 needs lives in the 78
//!   bytes that were `_reserved` (ctx offsets 178..256), read/written through
//!   [`V2Block`]. Contexts created by the v1 program have those bytes all zero, which
//!   decodes as "no v2 block" and keeps them on the exact v1 code path.
//! * Kinds 0 (Passive) and 1 (vAMM) keep their v1 pricing functions byte for byte
//!   (`compute_passive_execution` / `compute_vamm_execution` are not modified). v2 only
//!   adds, for those kinds, (a) clipping to a wrapper-supplied headroom and (b) the
//!   stale-mark guard, and both are inert unless the wrapper sends the call extension
//!   and/or the LP owner configures a v2 block.
//! * Kind 2 (Adaptive) is new and uses [`quote_adaptive`].
//! * The 67-byte call's bytes 43..67 were "must be zero". All-zero still means legacy.
//!   `ext_version == 1` carries [`CallExt`]. Any other value is rejected, so a v1-shaped
//!   caller is unaffected and a malformed extension fails closed.
//!
//! Every tunable is config stored in the context (set by [`crate::vamm`] tag 5), never a
//! constant; the `DEFAULT_*` values below are only what a fresh kind-2 context gets.

use solana_program::program_error::ProgramError;

// =============================================================================
// Error codes (ProgramError::Custom). 8001 is ERR_INCONSISTENT_LEG_ORACLE_PRICE.
// =============================================================================

/// The mark the wrapper priced this call at is older than the configured limit (either
/// the authoritative `mark_slot` in the call extension, or the observed-unchanged-price
/// fallback). Refused rather than zero-filled so the taker sees why.
pub const ERR_STALE_MARK: u32 = 8002;
/// `mark_slot` in the call extension is in the future relative to the Clock. The wrapper
/// never produces that; fail closed.
pub const ERR_MARK_SLOT_IN_FUTURE: u32 = 8003;
/// A kind-2 / observed-staleness context is bound to one asset and was called for another.
pub const ERR_ASSET_MISMATCH: u32 = 8004;
/// Owner-proof authentication (tag 5, auth mode 1) did not reproduce `ctx.lp_pda`.
pub const ERR_OWNER_PROOF_MISMATCH: u32 = 8005;

// =============================================================================
// Call extension (bytes 43..67 of the 67-byte tag-0 call; per-leg trailer in tag 3)
// =============================================================================

pub const CALL_EXT_OFFSET: usize = 43;
pub const CALL_EXT_LEN: usize = 24;
pub const CALL_EXT_VERSION_V1: u8 = 1;
/// Matcher-inventory-sync (2026-10-03): version 2 = the v1 block followed by the LP's REAL
/// signed engine position on this leg's asset (i128, bytes 24..40), attested by the wrapper.
/// When present the matcher prices and caps against that position instead of its own
/// `inventory_base` counter, which liquidations, ADL scaling, side resets and every other
/// out-of-matcher position change leave stale (upstream percolator-prog#406,
/// percolator-match#8). Only the wrapper can sign for `lp_pda`, so the field is authenticated.
pub const CALL_EXT_VERSION_V2: u8 = 2;
/// Length of a version-2 call extension (v1 block + i128 LP position).
pub const CALL_EXT_V2_LEN: usize = 40;
/// `lp_headroom_q` is present.
pub const EXT_FLAG_HEADROOM: u8 = 1 << 0;
/// `mark_slot` is present.
pub const EXT_FLAG_MARK_SLOT: u8 = 1 << 1;
/// The wrapper understands `crate::FLAG_REQUESTED_FEE_MASK` in the return flags and may
/// charge it. Without this bit the matcher never sets those bits, so a wrapper whose
/// `validate_matcher_return` rejects unknown flag bits (v18.2) is never broken.
pub const EXT_FLAG_ACCEPTS_FEE_REQUEST: u8 = 1 << 2;
/// The wrapper asserts this request only REDUCES the taker's existing position (never
/// opens or flips it). Lets a taker exit under a stale mark when the ctx allows reducing
/// fills (security review P2-1: exits must not be trapped by the stale guard). The matcher
/// cannot see the taker's position, so only the wrapper can make this claim.
pub const EXT_FLAG_TAKER_REDUCING: u8 = 1 << 3;
/// Bytes 2..4 carry `exec_band_bps`: the wrapper's oracle band on exec_price (P1 default
/// 500). The matcher prices within `min(max_total_bps, band)` so a banded wrapper gets a
/// clipped fill instead of reverting (security review P2-2 / P1 Custom(66)).
pub const EXT_FLAG_EXEC_BAND: u8 = 1 << 4;
const EXT_KNOWN_FLAGS: u8 = EXT_FLAG_HEADROOM
    | EXT_FLAG_MARK_SLOT
    | EXT_FLAG_ACCEPTS_FEE_REQUEST
    | EXT_FLAG_TAKER_REDUCING
    | EXT_FLAG_EXEC_BAND;

/// Parsed call extension.
///
/// Wire (offsets relative to the start of the 24-byte block; absolute call offset = +43):
/// ```text
/// 0      u8   ext_version   (0 = legacy: all 24 bytes must be zero; 1 = this layout)
/// 1      u8   ext_flags     (bit0 HEADROOM, bit1 MARK_SLOT, bit2 ACCEPTS_FEE_REQUEST,
///                           bit3 TAKER_REDUCING, bit4 EXEC_BAND; other bits must be 0)
/// 2..4   u16  exec_band_bps (must be 0 unless EXEC_BAND set)
/// 4..12  u64  mark_slot     slot of the last fresh oracle observation behind
///                           oracle_price_e6 (must be 0 unless MARK_SLOT set)
/// 12..20 u64  lp_headroom_q max |exec_size| the wrapper will accept in the direction
///                           of THIS request (u64::MAX = unbounded; must be 0 unless
///                           HEADROOM set)
/// 20..24 u32  reserved      (must be 0)
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CallExt {
    pub headroom_q: Option<u64>,
    pub mark_slot: Option<u64>,
    pub accepts_fee_request: bool,
    pub taker_reducing: bool,
    pub exec_band_bps: Option<u16>,
    /// v2 only: the LP's real signed engine position on this leg's asset before this call
    /// (before this batch, for tag 3). `None` for v0/v1 blocks.
    pub lp_position_q: Option<i128>,
}

impl CallExt {
    pub fn parse(b: &[u8]) -> Result<Self, ProgramError> {
        if b.len() != CALL_EXT_LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        match b[0] {
            0 => {
                if b.iter().any(|&x| x != 0) {
                    return Err(ProgramError::InvalidInstructionData);
                }
                Ok(Self::default())
            }
            CALL_EXT_VERSION_V1 => {
                let flags = b[1];
                if flags & !EXT_KNOWN_FLAGS != 0 {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let band = u16::from_le_bytes([b[2], b[3]]);
                if flags & EXT_FLAG_EXEC_BAND == 0 && band != 0 {
                    return Err(ProgramError::InvalidInstructionData);
                }
                if b[20..24].iter().any(|&x| x != 0) {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let mark_slot = u64::from_le_bytes(b[4..12].try_into().unwrap());
                let headroom = u64::from_le_bytes(b[12..20].try_into().unwrap());
                if flags & EXT_FLAG_MARK_SLOT == 0 && mark_slot != 0 {
                    return Err(ProgramError::InvalidInstructionData);
                }
                if flags & EXT_FLAG_HEADROOM == 0 && headroom != 0 {
                    return Err(ProgramError::InvalidInstructionData);
                }
                Ok(Self {
                    headroom_q: (flags & EXT_FLAG_HEADROOM != 0).then_some(headroom),
                    mark_slot: (flags & EXT_FLAG_MARK_SLOT != 0).then_some(mark_slot),
                    accepts_fee_request: flags & EXT_FLAG_ACCEPTS_FEE_REQUEST != 0,
                    taker_reducing: flags & EXT_FLAG_TAKER_REDUCING != 0,
                    exec_band_bps: (flags & EXT_FLAG_EXEC_BAND != 0).then_some(band),
                    lp_position_q: None,
                })
            }
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }

    /// Parse a 40-byte version-2 block: the first 24 bytes follow every v1 rule (flags,
    /// field-without-flag, reserved 20..24), the last 16 are the LP position. `i128::MIN`
    /// is refused (its magnitude is not representable and no real position reaches it).
    pub fn parse_v2(b: &[u8]) -> Result<Self, ProgramError> {
        if b.len() != CALL_EXT_V2_LEN || b[0] != CALL_EXT_VERSION_V2 {
            return Err(ProgramError::InvalidInstructionData);
        }
        let mut v1 = [0u8; CALL_EXT_LEN];
        v1.copy_from_slice(&b[..CALL_EXT_LEN]);
        v1[0] = CALL_EXT_VERSION_V1;
        let mut ext = Self::parse(&v1)?;
        let pos = i128::from_le_bytes(b[CALL_EXT_LEN..CALL_EXT_V2_LEN].try_into().unwrap());
        if pos == i128::MIN {
            return Err(ProgramError::InvalidInstructionData);
        }
        ext.lp_position_q = Some(pos);
        Ok(ext)
    }

    /// Parse either a 24-byte (v0/v1) or a 40-byte (v2) block, by length.
    pub fn parse_any(b: &[u8]) -> Result<Self, ProgramError> {
        match b.len() {
            CALL_EXT_LEN => Self::parse(b),
            CALL_EXT_V2_LEN => Self::parse_v2(b),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }

    pub fn is_legacy(&self) -> bool {
        self.headroom_q.is_none()
            && self.mark_slot.is_none()
            && !self.accepts_fee_request
            && !self.taker_reducing
            && self.exec_band_bps.is_none()
            && self.lp_position_q.is_none()
    }

    /// Encode as a version-2 block. `lp_position_q` must be `Some`.
    pub fn encode_v2(&self) -> [u8; CALL_EXT_V2_LEN] {
        let pos = self.lp_position_q.expect("encode_v2 needs lp_position_q");
        let mut b = [0u8; CALL_EXT_V2_LEN];
        let mut v1 = *self;
        v1.lp_position_q = None;
        // `encode` returns all-zero for a block with no v1 field; v2 still carries version 2.
        b[..CALL_EXT_LEN].copy_from_slice(&v1.encode_v1_fields());
        b[0] = CALL_EXT_VERSION_V2;
        b[CALL_EXT_LEN..].copy_from_slice(&pos.to_le_bytes());
        b
    }

    /// Encode as a 24-byte v0/v1 block. A v2-only field (`lp_position_q`) cannot be
    /// represented here and is not encoded; use [`Self::encode_v2`].
    pub fn encode(&self) -> [u8; CALL_EXT_LEN] {
        let mut v1 = *self;
        v1.lp_position_q = None;
        if v1.is_legacy() {
            return [0u8; CALL_EXT_LEN];
        }
        v1.encode_v1_fields()
    }

    fn encode_v1_fields(&self) -> [u8; CALL_EXT_LEN] {
        let mut b = [0u8; CALL_EXT_LEN];
        b[0] = CALL_EXT_VERSION_V1;
        let mut flags = 0u8;
        if let Some(s) = self.mark_slot {
            flags |= EXT_FLAG_MARK_SLOT;
            b[4..12].copy_from_slice(&s.to_le_bytes());
        }
        if let Some(h) = self.headroom_q {
            flags |= EXT_FLAG_HEADROOM;
            b[12..20].copy_from_slice(&h.to_le_bytes());
        }
        if self.accepts_fee_request {
            flags |= EXT_FLAG_ACCEPTS_FEE_REQUEST;
        }
        if self.taker_reducing {
            flags |= EXT_FLAG_TAKER_REDUCING;
        }
        if let Some(band) = self.exec_band_bps {
            flags |= EXT_FLAG_EXEC_BAND;
            b[2..4].copy_from_slice(&band.to_le_bytes());
        }
        b[1] = flags;
        b
    }
}

/// The matcher's quote expressed as a taker fee on mark-settled notional:
/// ceil(|exec - oracle| * 1e4 / oracle), capped at `crate::REQUESTED_FEE_BPS_MAX`.
///
/// Why: on v18.2 the wrapper settles every fill at the asset mark and uses the matcher's
/// exec_price only for the taker limit check / hybrid mark input (percolator-prog
/// `src/v16_program.rs` F-TRADENOCPI-FEE). A spread in exec_price therefore pays the LP
/// nothing. A wrapper that sets `EXT_FLAG_ACCEPTS_FEE_REQUEST` can charge this instead.
pub fn requested_fee_bps(oracle_e6: u64, exec_price_e6: u64) -> u32 {
    if oracle_e6 == 0 {
        return 0;
    }
    let o = oracle_e6 as u128;
    let d = (exec_price_e6 as u128).abs_diff(o);
    let bps = div_ceil(d * BPS, o);
    bps.min(crate::REQUESTED_FEE_BPS_MAX as u128) as u32
}

// =============================================================================
// V2 block (MatcherCtx._reserved, ctx offsets 178..256)
// =============================================================================

/// Absolute offset of the v2 block inside the MatcherCtx (== offset of `_reserved`).
pub const V2_BLOCK_CTX_OFFSET: usize = 178;
pub const V2_BLOCK_LEN: usize = 78;
pub const V2_BLOCK_VERSION: u8 = 1;
/// v2_flags bit0: when the mark is stale, still allow fills that REDUCE the LP's
/// |inventory| (clipped so they cannot flip it). Off by default: a stale close can be
/// as toxic as a stale open.
pub const V2_FLAG_STALE_ALLOW_REDUCING: u8 = 1 << 0;
const V2_KNOWN_FLAGS: u8 = V2_FLAG_STALE_ALLOW_REDUCING;

/// Owner-tunable v2 configuration.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct V2Config {
    pub flags: u8,
    /// Adaptive fee floor / ceiling / cold-start value (bps).
    pub fee_lo_bps: u16,
    pub fee_hi_bps: u16,
    pub fee_cold_bps: u16,
    /// fee = lo + a_milli/1000 * sigma + sigma^2 / b_den   (sigma in bps per ref horizon)
    pub vol_a_milli: u16,
    /// 0 disables the quadratic term.
    pub vol_b_den: u16,
    /// EWMA weight (bps) given to each new variance sample. 1..=10_000.
    pub vol_alpha_bps: u16,
    /// Samples required before the estimate replaces `fee_cold_bps`.
    pub vol_warmup: u8,
    /// Per-sample relative move cap, in units of 10 bps (1..=255 → 10..2550 bps).
    pub vol_move_cap_10bps: u8,
    /// Variance reference horizon in slots; one sample per >= this many slots.
    pub vol_ref_slots: u16,
    /// Thin-side rebate slope (bps at |inventory| == skew_ref_inventory). <= skew slope.
    pub thin_rebate_mult_bps: u16,
    /// Caps on the surcharge / rebate averages (bps). rebate_cap <= skew_cap <= 5000.
    pub skew_cap_bps: u16,
    pub rebate_cap_bps: u16,
    /// Refuse when Clock.slot - ext.mark_slot > this (0 disables).
    pub max_mark_age_slots: u16,
    /// Fallback without the extension: refuse when the oracle price handed to the matcher
    /// has not changed for more than this many slots (0 disables).
    pub observed_stale_slots: u16,
    /// Inventory (base q) at which the skew surcharge reaches `skew_spread_mult_bps`.
    pub skew_ref_inventory: u64,
}

/// Mutable v2 state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct V2State {
    pub vol_warmup_left: u8,
    /// asset_index + 1 this context is bound to (0 = unbound, binds on first call).
    pub bound_asset_plus1: u16,
    /// EWMA of the per-ref-horizon squared move, in bps^2 * 1e4.
    pub vol_var_e4: u64,
    pub vol_last_price_e6: u64,
    pub vol_last_slot: u64,
    pub obs_price_e6: u64,
    pub obs_since_slot: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct V2Block {
    pub cfg: V2Config,
    pub st: V2State,
}

/// Layout within the 78-byte block (offset + 178 = MatcherCtx offset):
/// ```text
///  0 u8  block_version (1)       1 u8  flags
///  2 u16 fee_lo_bps              4 u16 fee_hi_bps          6 u16 fee_cold_bps
///  8 u16 vol_a_milli            10 u16 vol_b_den          12 u16 vol_alpha_bps
/// 14 u8  vol_warmup_left        15 u8  vol_move_cap_10bps 16 u16 vol_ref_slots
/// 18 u16 thin_rebate_mult_bps   20 u16 skew_cap_bps       22 u16 rebate_cap_bps
/// 24 u16 max_mark_age_slots     26 u16 observed_stale_slots
/// 28 u16 bound_asset_plus1      30 u64 skew_ref_inventory
/// 38 u64 vol_var_e4             46 u64 vol_last_price_e6  54 u64 vol_last_slot
/// 62 u64 obs_price_e6           70 u64 obs_since_slot     (78 end)
/// ```
/// `vol_warmup` (config) is not stored separately: tag 5 writes it into
/// `vol_warmup_left`, which counts down.
impl V2Block {
    pub fn decode(r: &[u8; V2_BLOCK_LEN]) -> Option<Self> {
        if r[0] != V2_BLOCK_VERSION {
            return None;
        }
        let u16_at = |o: usize| u16::from_le_bytes([r[o], r[o + 1]]);
        let u64_at = |o: usize| u64::from_le_bytes(r[o..o + 8].try_into().unwrap());
        Some(Self {
            cfg: V2Config {
                flags: r[1],
                fee_lo_bps: u16_at(2),
                fee_hi_bps: u16_at(4),
                fee_cold_bps: u16_at(6),
                vol_a_milli: u16_at(8),
                vol_b_den: u16_at(10),
                vol_alpha_bps: u16_at(12),
                vol_warmup: 0,
                vol_move_cap_10bps: r[15],
                vol_ref_slots: u16_at(16),
                thin_rebate_mult_bps: u16_at(18),
                skew_cap_bps: u16_at(20),
                rebate_cap_bps: u16_at(22),
                max_mark_age_slots: u16_at(24),
                observed_stale_slots: u16_at(26),
                skew_ref_inventory: u64_at(30),
            },
            st: V2State {
                vol_warmup_left: r[14],
                bound_asset_plus1: u16_at(28),
                vol_var_e4: u64_at(38),
                vol_last_price_e6: u64_at(46),
                vol_last_slot: u64_at(54),
                obs_price_e6: u64_at(62),
                obs_since_slot: u64_at(70),
            },
        })
    }

    pub fn encode(&self) -> [u8; V2_BLOCK_LEN] {
        let mut r = [0u8; V2_BLOCK_LEN];
        let c = &self.cfg;
        let s = &self.st;
        r[0] = V2_BLOCK_VERSION;
        r[1] = c.flags;
        r[2..4].copy_from_slice(&c.fee_lo_bps.to_le_bytes());
        r[4..6].copy_from_slice(&c.fee_hi_bps.to_le_bytes());
        r[6..8].copy_from_slice(&c.fee_cold_bps.to_le_bytes());
        r[8..10].copy_from_slice(&c.vol_a_milli.to_le_bytes());
        r[10..12].copy_from_slice(&c.vol_b_den.to_le_bytes());
        r[12..14].copy_from_slice(&c.vol_alpha_bps.to_le_bytes());
        r[14] = s.vol_warmup_left;
        r[15] = c.vol_move_cap_10bps;
        r[16..18].copy_from_slice(&c.vol_ref_slots.to_le_bytes());
        r[18..20].copy_from_slice(&c.thin_rebate_mult_bps.to_le_bytes());
        r[20..22].copy_from_slice(&c.skew_cap_bps.to_le_bytes());
        r[22..24].copy_from_slice(&c.rebate_cap_bps.to_le_bytes());
        r[24..26].copy_from_slice(&c.max_mark_age_slots.to_le_bytes());
        r[26..28].copy_from_slice(&c.observed_stale_slots.to_le_bytes());
        r[28..30].copy_from_slice(&s.bound_asset_plus1.to_le_bytes());
        r[30..38].copy_from_slice(&c.skew_ref_inventory.to_le_bytes());
        r[38..46].copy_from_slice(&s.vol_var_e4.to_le_bytes());
        r[46..54].copy_from_slice(&s.vol_last_price_e6.to_le_bytes());
        r[54..62].copy_from_slice(&s.vol_last_slot.to_le_bytes());
        r[62..70].copy_from_slice(&s.obs_price_e6.to_le_bytes());
        r[70..78].copy_from_slice(&s.obs_since_slot.to_le_bytes());
        r
    }

    /// Fresh block with `cfg`, estimator cold, unbound.
    pub fn fresh(cfg: V2Config) -> Self {
        Self {
            cfg,
            st: V2State {
                vol_warmup_left: cfg.vol_warmup,
                ..V2State::default()
            },
        }
    }
}

// =============================================================================
// Defaults = backtest 'V2-tuned-A': best worst-case LP PnL under Mode A (v18.2 mark
// settlement), in- and out-of-sample (backtest/RESULTS.md). Pair with core params
// max_total 100, impact_k 5000, liquidity = 10x LP capital, skew_spread_mult 300.
// Only used when a kind-2 context is created through the fixed 78-byte tag-2 payload
// (wrapper tag 83), which has no room for v2 config. Every value is re-settable by
// tag 5. NOT calibrated on live Percolator flow — see the ledger note.
// =============================================================================

pub const DEFAULT_FEE_LO_BPS: u16 = 10;
pub const DEFAULT_FEE_HI_BPS: u16 = 80;
pub const DEFAULT_FEE_COLD_BPS: u16 = 10;
pub const DEFAULT_VOL_A_MILLI: u16 = 1000;
pub const DEFAULT_VOL_B_DEN: u16 = 100;
pub const DEFAULT_VOL_ALPHA_BPS: u16 = 1000;
pub const DEFAULT_VOL_WARMUP: u8 = 8;
pub const DEFAULT_VOL_MOVE_CAP_10BPS: u8 = 100; // 1000 bps
pub const DEFAULT_VOL_REF_SLOTS: u16 = 25; // ~10 s at 400 ms slots
pub const DEFAULT_SKEW_CAP_BPS: u16 = 100;
pub const DEFAULT_MAX_MARK_AGE_SLOTS: u16 = 150; // ~60 s
/// OFF by default (security review P2-1): an unchanged AUTH_MARK price is normal (the
/// keeper's #125 hold republishes the same mark; coarse e6 ticks sit flat), so the
/// heuristic misfires on healthy markets. Use the wrapper's mark_slot instead.
pub const DEFAULT_OBSERVED_STALE_SLOTS: u16 = 0;
/// Reducing fills stay allowed under a stale mark by default (P2-1: exits must not trap).
pub const DEFAULT_V2_FLAGS: u8 = V2_FLAG_STALE_ALLOW_REDUCING;

/// Upper bounds enforced by [`validate_config`].
pub const MAX_FEE_BPS: u16 = 1000;
pub const MAX_SKEW_CAP_BPS: u16 = 5000;
pub const MAX_IMPACT_K_BPS: u32 = 100_000;

/// Validate a v2 config against the core context parameters it prices with.
pub fn validate_config(
    c: &V2Config,
    kind: u8,
    base_spread_bps: u32,
    max_total_bps: u32,
    skew_spread_mult_bps: u16,
    impact_k_bps: u32,
    liquidity_notional_e6: u128,
) -> Result<(), ProgramError> {
    let bad = Err(ProgramError::InvalidAccountData);
    if c.flags & !V2_KNOWN_FLAGS != 0 {
        return bad;
    }
    if kind != 2 {
        // Kinds 0/1 only use the stale guard + binding fields; the pricing fields must be
        // zero so a later kind switch cannot inherit unvalidated values.
        let pricing_zero = c.fee_lo_bps == 0
            && c.fee_hi_bps == 0
            && c.fee_cold_bps == 0
            && c.vol_a_milli == 0
            && c.vol_b_den == 0
            && c.vol_alpha_bps == 0
            && c.vol_warmup == 0
            && c.vol_move_cap_10bps == 0
            && c.vol_ref_slots == 0
            && c.thin_rebate_mult_bps == 0
            && c.skew_cap_bps == 0
            && c.rebate_cap_bps == 0
            && c.skew_ref_inventory == 0;
        return if pricing_zero { Ok(()) } else { bad };
    }
    if !(c.fee_lo_bps <= c.fee_cold_bps && c.fee_cold_bps <= c.fee_hi_bps) {
        return bad;
    }
    if c.fee_hi_bps > MAX_FEE_BPS {
        return bad;
    }
    if (base_spread_bps as u64) + (c.fee_hi_bps as u64) > max_total_bps as u64 {
        return bad;
    }
    if c.vol_alpha_bps == 0 || c.vol_alpha_bps > 10_000 {
        return bad;
    }
    if c.vol_ref_slots == 0 || c.vol_move_cap_10bps == 0 {
        return bad;
    }
    if c.skew_cap_bps > MAX_SKEW_CAP_BPS || c.rebate_cap_bps > c.skew_cap_bps {
        return bad;
    }
    // Round-trip safety: a rebate slope above the surcharge slope would pay a trader to
    // push inventory out and back.
    if c.thin_rebate_mult_bps > skew_spread_mult_bps {
        return bad;
    }
    if (skew_spread_mult_bps > 0 || c.thin_rebate_mult_bps > 0) && c.skew_ref_inventory == 0 {
        return bad;
    }
    if impact_k_bps > MAX_IMPACT_K_BPS || (impact_k_bps > 0 && liquidity_notional_e6 == 0) {
        return bad;
    }
    Ok(())
}

/// Defaults for a kind-2 context created via the fixed tag-2 payload.
pub fn default_config_for_kind2(
    trading_fee_bps: u32,
    base_spread_bps: u32,
    max_total_bps: u32,
    skew_spread_mult_bps: u16,
    max_inventory_abs: u128,
) -> V2Config {
    let room = max_total_bps
        .saturating_sub(base_spread_bps)
        .min(MAX_FEE_BPS as u32) as u16;
    let fee_hi = DEFAULT_FEE_HI_BPS.min(room);
    let lo_want = (trading_fee_bps.min(MAX_FEE_BPS as u32) as u16).max(DEFAULT_FEE_LO_BPS);
    let fee_lo = lo_want.min(fee_hi);
    let fee_cold = DEFAULT_FEE_COLD_BPS.clamp(fee_lo, fee_hi);
    let skew_cap = DEFAULT_SKEW_CAP_BPS
        .min(MAX_SKEW_CAP_BPS)
        .min(max_total_bps.min(u16::MAX as u32) as u16);
    let skew_ref = if max_inventory_abs == 0 || max_inventory_abs > u64::MAX as u128 {
        u64::MAX
    } else {
        max_inventory_abs as u64
    };
    V2Config {
        flags: DEFAULT_V2_FLAGS,
        fee_lo_bps: fee_lo,
        fee_hi_bps: fee_hi,
        fee_cold_bps: fee_cold,
        vol_a_milli: DEFAULT_VOL_A_MILLI,
        vol_b_den: DEFAULT_VOL_B_DEN,
        vol_alpha_bps: DEFAULT_VOL_ALPHA_BPS,
        vol_warmup: DEFAULT_VOL_WARMUP,
        vol_move_cap_10bps: DEFAULT_VOL_MOVE_CAP_10BPS,
        vol_ref_slots: DEFAULT_VOL_REF_SLOTS,
        thin_rebate_mult_bps: skew_spread_mult_bps / 2,
        skew_cap_bps: skew_cap,
        rebate_cap_bps: skew_cap / 2,
        max_mark_age_slots: DEFAULT_MAX_MARK_AGE_SLOTS,
        observed_stale_slots: DEFAULT_OBSERVED_STALE_SLOTS,
        skew_ref_inventory: skew_ref,
    }
}

// =============================================================================
// Pure pricing arithmetic (Kani targets)
// =============================================================================

pub const BPS: u128 = 10_000;

/// Exact floor(sqrt(n)) for u64, fixed 32 iterations (bit-by-bit), so Kani can unwind it.
pub fn isqrt_u64(n: u64) -> u64 {
    let mut rem: u64 = n;
    let mut res: u64 = 0;
    let mut bit: u64 = 1u64 << 62;
    let mut i = 0;
    while i < 32 {
        if bit != 0 {
            let t = res + bit;
            if rem >= t {
                rem -= t;
                res = (res >> 1) + bit;
            } else {
                res >>= 1;
            }
            bit >>= 2;
        }
        i += 1;
    }
    res
}

/// Adaptive fee in bps. Depends ONLY on config + estimator state, never on trade size,
/// so the quote stays monotone in size. Result is always within [fee_lo, fee_hi].
pub fn adaptive_fee_bps(c: &V2Config, s: &V2State) -> u128 {
    let lo = c.fee_lo_bps as u128;
    let hi = (c.fee_hi_bps as u128).max(lo);
    if s.vol_warmup_left > 0 {
        return (c.fee_cold_bps as u128).clamp(lo, hi);
    }
    // vol_var_e4 is bps^2 * 1e4  =>  sqrt is sigma in bps * 100 ("centi-bps").
    let sigma_c = isqrt_u64(s.vol_var_e4) as u128;
    let lin = (c.vol_a_milli as u128) * sigma_c / 100_000;
    let quad = if c.vol_b_den == 0 {
        0
    } else {
        (s.vol_var_e4 as u128) / ((c.vol_b_den as u128) * 10_000)
    };
    (lo + lin + quad).clamp(lo, hi)
}

/// One estimator step. Samples at most once per `vol_ref_slots`; the squared move is
/// normalised to the reference horizon (diffusion scaling) and capped.
pub fn vol_update(c: &V2Config, s: &mut V2State, price_e6: u64, now_slot: u64) {
    if price_e6 == 0 {
        return;
    }
    if s.vol_last_price_e6 == 0 {
        s.vol_last_price_e6 = price_e6;
        s.vol_last_slot = now_slot;
        return;
    }
    if now_slot < s.vol_last_slot {
        return;
    }
    let dt = now_slot - s.vol_last_slot;
    let ref_slots = (c.vol_ref_slots as u64).max(1);
    if dt < ref_slots {
        return;
    }
    let last = s.vol_last_price_e6 as u128;
    let p = price_e6 as u128;
    let diff = p.abs_diff(last);
    let cap = (c.vol_move_cap_10bps as u128).max(1) * 10;
    let move_bps = (diff * BPS / last).min(cap);
    // bps^2 * 1e4, normalised by ref/dt (dt >= ref so this only scales down).
    let r2_e4 = move_bps * move_bps * 10_000 * (ref_slots as u128) / (dt as u128);
    let r2_e4 = r2_e4.min(cap * cap * 10_000);
    let var = s.vol_var_e4 as i128;
    let alpha = (c.vol_alpha_bps as i128).clamp(1, 10_000);
    let delta = (r2_e4 as i128 - var) * alpha / 10_000;
    let new_var = (var + delta).clamp(0, u64::MAX as i128);
    s.vol_var_e4 = new_var as u64;
    s.vol_warmup_left = s.vol_warmup_left.saturating_sub(1);
    s.vol_last_price_e6 = price_e6;
    s.vol_last_slot = now_slot;
}

/// ceil(a / b), b > 0.
#[inline]
fn div_ceil(a: u128, b: u128) -> u128 {
    a / b + u128::from(!a.is_multiple_of(b))
}

/// Constant-product-shaped impact in bps for a fill of `notional_e6` against virtual depth
/// `depth_e6`: ceil(k * n / (D - n)), where k = impact_k_bps (10_000 == exact CP).
/// `None` when n >= D (infinite impact).
pub fn cp_impact_bps(notional_e6: u128, depth_e6: u128, k_bps: u32) -> Option<u128> {
    if k_bps == 0 || notional_e6 == 0 {
        return Some(0);
    }
    if notional_e6 >= depth_e6 {
        return None;
    }
    let num = (k_bps as u128).checked_mul(notional_e6)?;
    Some(div_ceil(num, depth_e6 - notional_e6))
}

/// Largest notional whose CP impact is <= `budget_bps`: floor(B*D/(k+B)).
pub fn cp_max_notional_for_budget(depth_e6: u128, k_bps: u32, budget_bps: u128) -> u128 {
    if k_bps == 0 {
        return u128::MAX;
    }
    if budget_bps == 0 {
        return 0;
    }
    let denom = (k_bps as u128) + budget_bps;
    match budget_bps.checked_mul(depth_e6) {
        Some(num) => num / denom,
        // Divide first (slightly smaller result — conservative) when B*D would overflow.
        None => (depth_e6 / denom).saturating_mul(budget_bps),
    }
}

/// Skew potential numerator: `2*ref * W(x)` where `W(x) = ∫_0^x min(mult*t/ref, cap) dt`
/// (units bps·q). Quadratic `mult*x^2` up to the knee `xk = floor(cap*ref/mult)`, then
/// linear with slope `2*ref*cap`. Convex and non-decreasing in `x` (the slope at the knee,
/// `2*mult*xk`, is <= `2*ref*cap`). `None` on overflow (caller fails closed).
pub fn skew_potential_num(x: u128, mult_bps: u16, cap_bps: u16, ref_inv: u64) -> Option<u128> {
    if mult_bps == 0 || cap_bps == 0 || x == 0 {
        return Some(0);
    }
    let m = mult_bps as u128;
    let c = cap_bps as u128;
    let r = ref_inv as u128;
    let knee = c.checked_mul(r)? / m;
    if x <= knee {
        m.checked_mul(x)?.checked_mul(x)
    } else {
        let at_knee = m.checked_mul(knee)?.checked_mul(knee)?;
        let lin = (2u128)
            .checked_mul(r)?
            .checked_mul(c)?
            .checked_mul(x - knee)?;
        at_knee.checked_add(lin)
    }
}

/// Signed skew term (bps; positive = surcharge paid by the taker, negative = rebate) for the
/// LP inventory path `inv_pre -> inv_post`, as a fill-weighted average.
///
/// Cost = potential differences: moving |inventory| away from 0 costs `W_s(|end|) -
/// W_s(|start|)` (surcharge slope `s_mult`, cap `skew_cap`); moving it toward 0 earns
/// `W_r(|start|) - W_r(|end|)` (rebate slope `r_mult`, cap `rebate_cap`); a trade that
/// crosses 0 does both. Because each leg is a difference of a function of the endpoint
/// inventory alone, the total skew cost of any sequence of trades telescopes: splitting a
/// trade into pieces cannot reduce it (up to the final per-trade ceil, which only rounds
/// toward the LP). With `r <= s` and `rebate_cap <= skew_cap`, `W_r <= W_s` pointwise, so a
/// round trip from flat never nets the taker a rebate. Convexity of W makes the average,
/// and hence the quote, monotone non-decreasing in size.
///
/// All arithmetic is exact over the common denominator `2*ref*fill`; the single final
/// division rounds toward +inf (toward the LP).
#[allow(clippy::too_many_arguments)]
pub fn skew_net_bps(
    inv_pre: i128,
    fill: u128,
    lp_sells: bool,
    s_mult_bps: u16,
    r_mult_bps: u16,
    skew_cap_bps: u16,
    rebate_cap_bps: u16,
    ref_inv: u64,
) -> Option<i128> {
    if fill == 0 || ref_inv == 0 || (s_mult_bps == 0 && r_mult_bps == 0) {
        return Some(0);
    }
    let delta = i128::try_from(fill).ok()?;
    let inv_post = if lp_sells {
        inv_pre.checked_sub(delta)?
    } else {
        inv_pre.checked_add(delta)?
    };
    let a = inv_pre.unsigned_abs();
    let b = inv_post.unsigned_abs();
    let crosses = (inv_pre > 0 && inv_post < 0) || (inv_pre < 0 && inv_post > 0);
    let ws = |x: u128| skew_potential_num(x, s_mult_bps, skew_cap_bps, ref_inv);
    let wr = |x: u128| skew_potential_num(x, r_mult_bps, rebate_cap_bps, ref_inv);
    let (pos, neg) = if crosses {
        (ws(b)?, wr(a)?)
    } else if b >= a {
        (ws(b)?.checked_sub(ws(a)?)?, 0)
    } else {
        (0, wr(a)?.checked_sub(wr(b)?)?)
    };
    let den = (2u128).checked_mul(ref_inv as u128)?.checked_mul(fill)?;
    if pos >= neg {
        i128::try_from(div_ceil(pos - neg, den)).ok()
    } else {
        // round toward +inf: -floor(x)
        i128::try_from((neg - pos) / den).ok().map(|v| -v)
    }
}

/// Price a total spread onto the oracle, rounding toward the LP.
pub fn price_with_total_bps(oracle_e6: u64, total_bps: u128, taker_buys: bool) -> Option<u64> {
    if total_bps > BPS {
        return None;
    }
    let o = oracle_e6 as u128;
    let p = if taker_buys {
        div_ceil(o.checked_mul(BPS + total_bps)?, BPS)
    } else {
        o.checked_mul(BPS - total_bps)? / BPS
    };
    if p == 0 || p > u64::MAX as u128 {
        return None;
    }
    Some(p as u64)
}

/// Inputs to the kind-2 quote (all already clipped for max_fill / inventory / headroom).
#[derive(Clone, Copy, Debug)]
pub struct AdaptiveQuoteIn {
    pub oracle_e6: u64,
    pub fill: u128,
    pub taker_buys: bool,
    pub inv_pre: i128,
    pub base_spread_bps: u32,
    pub max_total_bps: u32,
    pub fee_bps: u128,
    pub impact_k_bps: u32,
    pub depth_e6: u128,
    pub s_mult_bps: u16,
    pub r_mult_bps: u16,
    pub skew_cap_bps: u16,
    pub rebate_cap_bps: u16,
    pub ref_inv: u64,
}

/// Kind-2 quote. Returns (fill, exec_price, total_bps). The fill may be reduced so the
/// total spread stays within max_total (size clip instead of v1's price clamp, which
/// handed large trades a free option). `fill == 0` means zero-fill.
pub fn quote_adaptive(q: &AdaptiveQuoteIn) -> Option<(u128, u64, u128)> {
    let max_total = (q.max_total_bps as u128).min(9_000);
    if q.fill == 0 {
        return Some((0, q.oracle_e6, 0));
    }
    // Largest feasible fill f* = max{ f : gross_pos(f) <= max_total }, where gross_pos
    // counts the surcharge only (a rebate never loosens the size limit). gross_pos is
    // non-decreasing in f (impact and surcharge both are), so the feasible set is a prefix
    // [0, f*] independent of the request and fill = min(request, f*) is monotone in the
    // requested size. (The earlier version sized the impact budget with the skew at the
    // REQUESTED size, so a larger request could shrink the fill — P2 backtest `-- probe`.)
    let fill = if gross_pos_bps(q, q.fill)? <= max_total {
        q.fill
    } else {
        // Invariant: gross_pos(lo) <= max (lo = 0 trivially), gross_pos(hi) > max.
        let mut lo: u128 = 0;
        let mut hi: u128 = q.fill;
        let mut i = 0;
        while hi - lo > 1 && i < 128 {
            let mid = lo + (hi - lo) / 2;
            if gross_pos_bps(q, mid)? <= max_total {
                lo = mid;
            } else {
                hi = mid;
            }
            i += 1;
        }
        lo
    };
    // A request that REDUCES the LP's |inventory| is always fillable up to |inventory|
    // (priced at the max_total clamp if it must be): the size clip exists to stop the LP
    // loading up, not to trap exits when the adaptive fee saturates in volatility
    // (LiteSVM finding D). max() of two request-monotone terms stays monotone.
    let lp_reduces = (q.taker_buys && q.inv_pre > 0) || (!q.taker_buys && q.inv_pre < 0);
    let fill = if lp_reduces {
        fill.max(q.fill.min(q.inv_pre.unsigned_abs()))
    } else {
        fill
    };
    if fill == 0 {
        return Some((0, q.oracle_e6, 0));
    }
    let (impact, skew) = impact_and_skew(q, fill)?;
    // An exempt reducing fill can reach the depth (infinite impact); the clamp prices it.
    let impact = impact.min(9_000);
    let gross = (q.base_spread_bps as u128 + q.fee_bps + impact) as i128 + skew;
    // Never below 0 (price never crosses the oracle in the taker's favour), never above
    // max_total.
    let total = (gross.max(0) as u128).min(max_total);
    let price = price_with_total_bps(q.oracle_e6, total, q.taker_buys)?;
    Some((fill, price, total))
}

/// (impact bps, signed skew bps) at `fill`; impact is u128::MAX (infeasible) when the
/// notional reaches the virtual depth.
fn impact_and_skew(q: &AdaptiveQuoteIn, fill: u128) -> Option<(u128, i128)> {
    let notional = fill.checked_mul(q.oracle_e6 as u128)? / 1_000_000;
    let impact = if q.impact_k_bps > 0 && notional >= q.depth_e6 {
        u128::MAX
    } else {
        cp_impact_bps(notional, q.depth_e6, q.impact_k_bps)?
    };
    let skew = skew_net_bps(
        q.inv_pre,
        fill,
        q.taker_buys,
        q.s_mult_bps,
        q.r_mult_bps,
        q.skew_cap_bps,
        q.rebate_cap_bps,
        q.ref_inv,
    )?;
    Some((impact, skew))
}

/// base + fee + impact + max(skew, 0), saturating (u128::MAX == infeasible).
fn gross_pos_bps(q: &AdaptiveQuoteIn, fill: u128) -> Option<u128> {
    if fill == 0 {
        return Some(0);
    }
    let (impact, skew) = impact_and_skew(q, fill)?;
    Some(
        (q.base_spread_bps as u128)
            .saturating_add(q.fee_bps)
            .saturating_add(impact)
            .saturating_add(skew.max(0) as u128),
    )
}

// =============================================================================
// Stale-mark guard (pure)
// =============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MarkState {
    Fresh,
    Stale,
    FutureSlot,
}

/// Decide mark freshness and advance the observed-price tracker.
/// `obs` = (obs_price_e6, obs_since_slot); updated in place on a fresh observation.
pub fn mark_state(
    c: &V2Config,
    obs: &mut (u64, u64),
    ext_mark_slot: Option<u64>,
    oracle_e6: u64,
    now_slot: u64,
) -> MarkState {
    let mut stale = false;
    if let Some(ms) = ext_mark_slot {
        if ms > now_slot {
            return MarkState::FutureSlot;
        }
        if c.max_mark_age_slots > 0 && now_slot - ms > c.max_mark_age_slots as u64 {
            stale = true;
        }
    }
    if c.observed_stale_slots > 0 {
        if obs.0 != oracle_e6 || obs.1 > now_slot {
            *obs = (oracle_e6, now_slot);
        } else if ext_mark_slot.is_none() && now_slot - obs.1 > c.observed_stale_slots as u64 {
            // Only without an authoritative mark_slot: a fresh wrapper mark_slot proves the
            // keeper alive (backtest: the fallback otherwise refused benign fills).
            stale = true;
        }
    }
    if stale {
        MarkState::Stale
    } else {
        MarkState::Fresh
    }
}

// =============================================================================
// Kani proofs — pricing arithmetic. Every harness carries cover!() properties so a
// SUCCESSFUL result is shown to be non-vacuous (the covers must be SATISFIED).
// Run locally: `cargo kani --harness <name>` (never in CI).
// =============================================================================

#[cfg(kani)]
mod proofs {
    use super::*;

    fn any_cfg_kind2() -> V2Config {
        let c = V2Config {
            flags: kani::any(),
            fee_lo_bps: kani::any(),
            fee_hi_bps: kani::any(),
            fee_cold_bps: kani::any(),
            vol_a_milli: kani::any(),
            vol_b_den: kani::any(),
            vol_alpha_bps: kani::any(),
            vol_warmup: kani::any(),
            vol_move_cap_10bps: kani::any(),
            vol_ref_slots: kani::any(),
            thin_rebate_mult_bps: kani::any(),
            skew_cap_bps: kani::any(),
            rebate_cap_bps: kani::any(),
            max_mark_age_slots: kani::any(),
            observed_stale_slots: kani::any(),
            skew_ref_inventory: kani::any(),
        };
        c
    }

    /// Adaptive fee always lies in [fee_lo, fee_hi] for a valid config and ANY estimator
    /// state, and never overflows.
    #[kani::proof]
    #[kani::solver(cadical)]
    #[kani::unwind(34)]
    fn proof_adaptive_fee_bounded() {
        let c = any_cfg_kind2();
        kani::assume(c.fee_lo_bps <= c.fee_cold_bps && c.fee_cold_bps <= c.fee_hi_bps);
        let s = V2State {
            vol_warmup_left: kani::any(),
            bound_asset_plus1: 0,
            vol_var_e4: kani::any(),
            vol_last_price_e6: 0,
            vol_last_slot: 0,
            obs_price_e6: 0,
            obs_since_slot: 0,
        };
        // Realistic bound: the estimator caps each sample at (2550 bps)^2 * 1e4 < 2^36.
        kani::assume(s.vol_var_e4 < (1u64 << 40));
        let f = adaptive_fee_bps(&c, &s);
        assert!(f >= c.fee_lo_bps as u128 && f <= c.fee_hi_bps as u128);
        kani::cover!(
            s.vol_warmup_left == 0 && f > c.fee_lo_bps as u128 && f < c.fee_hi_bps as u128
        );
        kani::cover!(
            s.vol_warmup_left == 0 && f == c.fee_hi_bps as u128 && c.fee_hi_bps > c.fee_lo_bps
        );
    }

    /// Adaptive fee is monotone non-decreasing in estimated variance.
    #[kani::proof]
    #[kani::solver(cadical)]
    #[kani::unwind(34)]
    fn proof_adaptive_fee_monotone_in_vol() {
        let c = any_cfg_kind2();
        kani::assume(c.fee_lo_bps <= c.fee_hi_bps);
        let v1: u64 = kani::any();
        let v2: u64 = kani::any();
        kani::assume(v1 <= v2 && v2 < (1u64 << 40));
        let mut s = V2State::default();
        s.vol_var_e4 = v1;
        let f1 = adaptive_fee_bps(&c, &s);
        s.vol_var_e4 = v2;
        let f2 = adaptive_fee_bps(&c, &s);
        assert!(f1 <= f2);
        kani::cover!(f1 < f2);
    }

    /// isqrt is exact floor sqrt (bounded domain to keep the solver fast).
    #[kani::proof]
    #[kani::solver(cadical)]
    #[kani::unwind(34)]
    fn proof_isqrt_exact() {
        let n: u64 = kani::any();
        kani::assume(n < (1u64 << 32));
        let r = isqrt_u64(n);
        assert!(r < (1u64 << 16) + 1);
        assert!(r * r <= n);
        assert!((r + 1) * (r + 1) > n);
        kani::cover!(r > 1000);
    }

    /// CP impact is monotone non-decreasing in notional, and the budget inverse is sound:
    /// impact(max_notional_for_budget(B)) <= B.
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_cp_impact_monotone_and_budget_sound() {
        let d: u128 = kani::any();
        let k: u32 = kani::any();
        let n1: u128 = kani::any();
        let n2: u128 = kani::any();
        kani::assume(d > 0 && d < (1u128 << 40));
        kani::assume(k <= MAX_IMPACT_K_BPS);
        kani::assume(n1 <= n2 && n2 < d);
        let i1 = cp_impact_bps(n1, d, k).unwrap();
        let i2 = cp_impact_bps(n2, d, k).unwrap();
        assert!(i1 <= i2);
        let b: u128 = kani::any();
        kani::assume(b <= 9_000);
        let nmax = cp_max_notional_for_budget(d, k, b);
        if k > 0 && nmax < d {
            assert!(cp_impact_bps(nmax, d, k).unwrap() <= b);
        }
        kani::cover!(i1 < i2);
        kani::cover!(k > 0 && b > 0 && nmax > 0 && nmax < d);
    }

    fn skew_args() -> (i128, u16, u16, u16, u16, u64) {
        let inv: i128 = kani::any();
        let s: u16 = kani::any();
        let r: u16 = kani::any();
        let sc: u16 = kani::any();
        let rc: u16 = kani::any();
        let rf: u64 = kani::any();
        kani::assume(inv > -(1i128 << 20) && inv < (1i128 << 20));
        kani::assume(s <= 10_000 && r <= s);
        kani::assume(sc <= MAX_SKEW_CAP_BPS && rc <= sc);
        kani::assume(rf > 0 && rf < (1u64 << 20));
        (inv, s, r, sc, rc, rf)
    }

    /// Skew term is monotone non-decreasing in fill size (either direction).
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_skew_monotone_in_size() {
        let (inv, s, r, sc, rc, rf) = skew_args();
        let lp_sells: bool = kani::any();
        let f1: u128 = kani::any();
        let f2: u128 = kani::any();
        kani::assume(f1 > 0 && f1 <= f2 && f2 < (1u128 << 20));
        let a = skew_net_bps(inv, f1, lp_sells, s, r, sc, rc, rf).unwrap();
        let b = skew_net_bps(inv, f2, lp_sells, s, r, sc, rc, rf).unwrap();
        assert!(a <= b);
        kani::cover!(a < 0 && b > 0); // crosses from rebate to surcharge
        kani::cover!(a > 0 && a < b);
    }

    /// Skew term is monotone non-decreasing in pre-trade skew in the trade's direction:
    /// for an LP that sells (taker buys), a more-negative starting inventory costs more.
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_skew_monotone_in_skew() {
        let (inv, s, r, sc, rc, rf) = skew_args();
        let f: u128 = kani::any();
        kani::assume(f > 0 && f < (1u128 << 20));
        let lower: i128 = kani::any();
        kani::assume(lower > -(1i128 << 20) && lower <= inv);
        // LP sells => inventory decreases => starting lower (more short) is worse.
        let a = skew_net_bps(inv, f, true, s, r, sc, rc, rf).unwrap();
        let b = skew_net_bps(lower, f, true, s, r, sc, rc, rf).unwrap();
        assert!(a <= b);
        kani::cover!(a < b && a < 0);
    }

    /// No splitting profit from the rebate: going out and straight back never nets the
    /// taker a positive skew payment (r <= s), measured in bps*units.
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_skew_round_trip_non_negative() {
        let (inv, s, r, sc, rc, rf) = skew_args();
        let f: u128 = kani::any();
        kani::assume(f > 0 && f < (1u128 << 20));
        let lp_sells: bool = kani::any();
        let out = skew_net_bps(inv, f, lp_sells, s, r, sc, rc, rf).unwrap();
        let mid = if lp_sells {
            inv - f as i128
        } else {
            inv + f as i128
        };
        let back = skew_net_bps(mid, f, !lp_sells, s, r, sc, rc, rf).unwrap();
        // Only meaningful from a flat start (organic skew legitimately pays the rebalancer).
        if inv == 0 {
            assert!(out + back >= 0);
        }
        kani::cover!(inv == 0 && out > 0 && back < 0);
    }

    /// Splitting a trade into two pieces never pays less skew (bps·q, before the per-trade
    /// ceil the pieces can only round up): potential differences telescope exactly.
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_skew_split_never_cheaper() {
        let (inv, s, r, sc, rc, rf) = skew_args();
        let f1: u128 = kani::any();
        let f2: u128 = kani::any();
        kani::assume(f1 > 0 && f2 > 0 && f1 < (1u128 << 16) && f2 < (1u128 << 16));
        let lp_sells: bool = kani::any();
        let whole = skew_net_bps(inv, f1 + f2, lp_sells, s, r, sc, rc, rf).unwrap();
        let p1 = skew_net_bps(inv, f1, lp_sells, s, r, sc, rc, rf).unwrap();
        let mid = if lp_sells {
            inv - f1 as i128
        } else {
            inv + f1 as i128
        };
        let p2 = skew_net_bps(mid, f2, lp_sells, s, r, sc, rc, rf).unwrap();
        // cost in bps*q; each call rounds toward +inf so pieces >= exact, whole <= exact+f.
        let split_cost = p1 * f1 as i128 + p2 * f2 as i128;
        let whole_cost = whole * (f1 + f2) as i128;
        assert!(split_cost + (f1 + f2) as i128 >= whole_cost);
        kani::cover!(sc > 0 && s > 0 && p2 > p1);
    }

    fn any_quote() -> AdaptiveQuoteIn {
        let q = AdaptiveQuoteIn {
            oracle_e6: kani::any(),
            fill: kani::any(),
            taker_buys: kani::any(),
            inv_pre: kani::any(),
            base_spread_bps: kani::any(),
            max_total_bps: kani::any(),
            fee_bps: kani::any(),
            impact_k_bps: kani::any(),
            depth_e6: kani::any(),
            s_mult_bps: kani::any(),
            r_mult_bps: kani::any(),
            skew_cap_bps: kani::any(),
            rebate_cap_bps: kani::any(),
            ref_inv: kani::any(),
        };
        kani::assume(q.oracle_e6 >= 1 && q.oracle_e6 < (1u64 << 32));
        kani::assume(q.fill < (1u128 << 20));
        kani::assume(q.inv_pre > -(1i128 << 20) && q.inv_pre < (1i128 << 20));
        kani::assume(q.max_total_bps <= 9_000 && q.base_spread_bps <= 9_000);
        kani::assume(q.fee_bps <= MAX_FEE_BPS as u128);
        kani::assume(q.impact_k_bps <= MAX_IMPACT_K_BPS);
        kani::assume(q.depth_e6 < (1u128 << 40));
        kani::assume(q.s_mult_bps <= 10_000 && q.r_mult_bps <= q.s_mult_bps);
        kani::assume(q.skew_cap_bps <= MAX_SKEW_CAP_BPS && q.rebate_cap_bps <= q.skew_cap_bps);
        kani::assume(q.ref_inv > 0 && q.ref_inv < (1u64 << 20));
        q
    }

    /// The quote never prices through the oracle in the taker's favour, never exceeds
    /// max_total, never grows the fill, and never overflows (returns Some).
    #[kani::proof]
    #[kani::solver(cadical)]
    #[kani::unwind(24)]
    fn proof_quote_never_crosses_oracle() {
        let q = any_quote();
        if let Some((fill, price, total)) = quote_adaptive(&q) {
            assert!(fill <= q.fill);
            assert!(total <= q.max_total_bps as u128);
            if fill > 0 {
                if q.taker_buys {
                    assert!(price >= q.oracle_e6);
                } else {
                    assert!(price <= q.oracle_e6);
                }
            } else {
                assert!(price == q.oracle_e6);
            }
            kani::cover!(fill > 0 && q.taker_buys && price > q.oracle_e6);
            kani::cover!(fill > 0 && !q.taker_buys && price < q.oracle_e6);
            kani::cover!(fill > 0 && fill < q.fill); // size clip exercised
        }
    }

    /// Realised fill is monotone non-decreasing in the REQUESTED size (fixed state).
    #[kani::proof]
    #[kani::solver(cadical)]
    #[kani::unwind(24)]
    fn proof_quote_fill_monotone_in_request() {
        let q = any_quote();
        let bigger: u128 = kani::any();
        kani::assume(bigger >= q.fill && bigger < (1u128 << 20));
        let mut q2 = q;
        q2.fill = bigger;
        if let (Some((f1, _, _)), Some((f2, _, _))) = (quote_adaptive(&q), quote_adaptive(&q2)) {
            assert!(f1 <= f2);
            kani::cover!(f1 > 0 && f1 < q.fill);
        }
    }

    /// Stale guard: whenever an authoritative mark_slot older than the limit is supplied,
    /// the guard reports Stale (so the caller refuses) — no path prices through it.
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_stale_mark_never_fresh() {
        let c = any_cfg_kind2();
        let mut obs: (u64, u64) = (kani::any(), kani::any());
        let now: u64 = kani::any();
        let ms: u64 = kani::any();
        let px: u64 = kani::any();
        let st = mark_state(&c, &mut obs, Some(ms), px, now);
        if ms > now {
            assert!(st == MarkState::FutureSlot);
        } else if c.max_mark_age_slots > 0 && now - ms > c.max_mark_age_slots as u64 {
            assert!(st == MarkState::Stale);
        }
        kani::cover!(st == MarkState::Stale);
        kani::cover!(st == MarkState::Fresh && c.max_mark_age_slots > 0);
    }

    /// Observed-staleness fallback: an unchanged price older than the limit is Stale; a
    /// changed price is always Fresh (w.r.t. the fallback) and resets the tracker.
    #[kani::proof]
    #[kani::solver(cadical)]
    fn proof_observed_stale() {
        let mut c = any_cfg_kind2();
        c.max_mark_age_slots = 0;
        let p0: u64 = kani::any();
        let since: u64 = kani::any();
        let now: u64 = kani::any();
        let px: u64 = kani::any();
        kani::assume(since <= now);
        let mut obs = (p0, since);
        let st = mark_state(&c, &mut obs, None, px, now);
        if c.observed_stale_slots > 0 && px == p0 && now - since > c.observed_stale_slots as u64 {
            assert!(st == MarkState::Stale);
        }
        if px != p0 {
            assert!(st == MarkState::Fresh);
            if c.observed_stale_slots > 0 {
                assert!(obs == (px, now));
            }
        }
        kani::cover!(st == MarkState::Stale);
    }
}
