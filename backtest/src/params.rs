//! Parameter sets, all expressed as real `MatcherCtx` configs.
//!
//! Units: base unit q with 1 token = 1_000_000 q, prices in e6 USD, so
//! notional_e6 = q * price_e6 / 1e6 is micro-USD (the same convention the launch wizard
//! uses: `maxInventoryAbs = inventoryCapAtoms * 1e6 / priceE6` with 6-decimal collateral).

use percolator_match::v2::{self, V2Block, V2Config};
use percolator_match::vamm::{MatcherCtx, MATCHER_MAGIC, MATCHER_VERSION};

pub const LP_CAPITAL_USD: f64 = 10_000.0;
pub const LP_LEVERAGE: u64 = 10;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct V2Knobs {
    pub fee_lo: u16,
    pub fee_hi: u16,
    /// None = crate default (80) clamped into [lo, hi].
    pub fee_cold: Option<u16>,
    pub vol_a_milli: u16,
    pub vol_b_den: u16,
    pub vol_ref_slots: u16,
    pub thin_rebate_half: bool,
    pub max_mark_age_slots: u16,
    pub observed_stale_slots: u16,
}

#[derive(Clone, Debug)]
pub enum V2Mode {
    /// No v2 block (exact v1 path for kinds 0/1).
    None,
    /// `v2::default_config_for_kind2(...)` on the core params (optionally overriding
    /// the stale-guard fields).
    Default {
        max_mark_age: Option<u16>,
        observed: Option<u16>,
    },
    /// Custom v2 config built from knobs (other fields = crate defaults).
    Custom(V2Knobs),
    /// Kinds 0/1 only: a v2 block carrying just the stale guard (pricing fields zero).
    GuardOnly { max_mark_age: u16, observed: u16 },
}

#[derive(Clone, Debug)]
pub struct Spec {
    pub name: String,
    pub kind: u8,
    pub trading_fee_bps: u32,
    pub base_spread_bps: u32,
    pub max_total_bps: u32,
    pub impact_k_bps: u32,
    /// Liquidity notional as a multiple of LP capital (0 = none).
    pub liq_mult_capital: f64,
    pub skew_mult_bps: u16,
    /// max_fill_abs = max_inventory_abs / max_fill_div
    pub max_fill_div: u32,
    pub v2: V2Mode,
}

impl Spec {
    pub fn v1_deployed() -> Self {
        Spec {
            name: "V1-deployed".into(),
            kind: 0,
            trading_fee_bps: 10,
            base_spread_bps: 50,
            max_total_bps: 200,
            impact_k_bps: 0,
            liq_mult_capital: 0.0,
            skew_mult_bps: 50,
            max_fill_div: 4,
            v2: V2Mode::None,
        }
    }
    pub fn v1_kind1() -> Self {
        Spec {
            name: "V1-kind1".into(),
            kind: 1,
            impact_k_bps: 100,
            liq_mult_capital: LP_LEVERAGE as f64, // = LP capacity notional
            ..Self::v1_deployed()
        }
    }
    pub fn v2_default() -> Self {
        Spec {
            name: "V2-default".into(),
            kind: 2,
            trading_fee_bps: 10,
            base_spread_bps: 20,
            max_total_bps: 400,
            impact_k_bps: 10_000,
            liq_mult_capital: 10.0,
            skew_mult_bps: 100,
            max_fill_div: 4,
            v2: V2Mode::Default {
                max_mark_age: None,
                observed: None,
            },
        }
    }
    pub fn v2_custom(name: &str, k: V2Knobs, skew: u16, impact_k: u32) -> Self {
        Spec {
            name: name.into(),
            skew_mult_bps: skew,
            impact_k_bps: impact_k,
            v2: V2Mode::Custom(k),
            ..Self::v2_default()
        }
    }
}

/// Knobs equal to the crate defaults (what `default_config_for_kind2` produces for the
/// V2-default core params).
pub fn default_knobs() -> V2Knobs {
    V2Knobs {
        fee_lo: v2::DEFAULT_FEE_LO_BPS,
        fee_hi: v2::DEFAULT_FEE_HI_BPS,
        fee_cold: None,
        vol_a_milli: v2::DEFAULT_VOL_A_MILLI,
        vol_b_den: v2::DEFAULT_VOL_B_DEN,
        vol_ref_slots: v2::DEFAULT_VOL_REF_SLOTS,
        thin_rebate_half: true,
        max_mark_age_slots: v2::DEFAULT_MAX_MARK_AGE_SLOTS,
        observed_stale_slots: v2::DEFAULT_OBSERVED_STALE_SLOTS,
    }
}

/// Custom kind-2 config: start from the crate's `default_config_for_kind2` (so flags,
/// alpha, warmup, move cap, skew/rebate caps track the crate defaults) and override the
/// swept knobs.
pub fn knobs_to_config(k: &V2Knobs, spec: &Spec, max_inv: u128) -> V2Config {
    let mut c = v2::default_config_for_kind2(
        spec.trading_fee_bps,
        spec.base_spread_bps,
        spec.max_total_bps,
        spec.skew_mult_bps,
        max_inv,
    );
    c.fee_lo_bps = k.fee_lo;
    c.fee_hi_bps = k.fee_hi;
    c.fee_cold_bps = k
        .fee_cold
        .unwrap_or(v2::DEFAULT_FEE_COLD_BPS)
        .clamp(k.fee_lo, k.fee_hi);
    c.vol_a_milli = k.vol_a_milli;
    c.vol_b_den = k.vol_b_den;
    c.vol_ref_slots = k.vol_ref_slots;
    c.thin_rebate_mult_bps = if k.thin_rebate_half {
        spec.skew_mult_bps / 2
    } else {
        0
    };
    c.max_mark_age_slots = k.max_mark_age_slots;
    c.observed_stale_slots = k.observed_stale_slots;
    c
}

/// Build and validate the context for a tape whose opening price is `open_e6`.
pub fn build_ctx(spec: &Spec, open_e6: u64) -> Result<MatcherCtx, String> {
    let capital_atoms = (LP_CAPITAL_USD * 1e6) as u128;
    let capacity_atoms = capital_atoms * LP_LEVERAGE as u128;
    let inv_cap_atoms = capacity_atoms * 40 / 100;
    let max_inv = inv_cap_atoms * 1_000_000 / open_e6.max(1) as u128;
    let max_fill = max_inv / spec.max_fill_div.max(1) as u128;
    let liq = (spec.liq_mult_capital * LP_CAPITAL_USD * 1e6) as u128;
    let mut ctx = MatcherCtx {
        magic: MATCHER_MAGIC,
        version: MATCHER_VERSION,
        kind: spec.kind,
        lp_pda: [1; 32],
        trading_fee_bps: spec.trading_fee_bps,
        base_spread_bps: spec.base_spread_bps,
        max_total_bps: spec.max_total_bps,
        impact_k_bps: spec.impact_k_bps,
        liquidity_notional_e6: liq,
        max_fill_abs: max_fill,
        max_inventory_abs: max_inv,
        skew_spread_mult_bps: spec.skew_mult_bps,
        lp_account_id: 1,
        ..MatcherCtx::default()
    };
    match &spec.v2 {
        V2Mode::None => {}
        V2Mode::Default {
            max_mark_age,
            observed,
        } => {
            let mut cfg = v2::default_config_for_kind2(
                spec.trading_fee_bps,
                spec.base_spread_bps,
                spec.max_total_bps,
                spec.skew_mult_bps,
                max_inv,
            );
            if let Some(a) = max_mark_age {
                cfg.max_mark_age_slots = *a;
            }
            if let Some(o) = observed {
                cfg.observed_stale_slots = *o;
            }
            ctx.set_v2_block(&V2Block::fresh(cfg));
        }
        V2Mode::Custom(k) => {
            let cfg = knobs_to_config(k, spec, max_inv);
            ctx.set_v2_block(&V2Block::fresh(cfg));
        }
        V2Mode::GuardOnly {
            max_mark_age,
            observed,
        } => {
            let cfg = V2Config {
                max_mark_age_slots: *max_mark_age,
                observed_stale_slots: *observed,
                flags: v2::DEFAULT_V2_FLAGS,
                ..V2Config::default()
            };
            ctx.set_v2_block(&V2Block::fresh(cfg));
        }
    }
    ctx.validate()
        .map_err(|e| format!("{}: ctx.validate() failed: {e:?}", spec.name))?;
    Ok(ctx)
}
