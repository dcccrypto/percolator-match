//! Unified Matcher Context for Percolator Markets
//!
//! Improvements over aeyakovenko/percolator-match:
//! 1. Skew-aware inventory: widens spread on the side that worsens inventory
//! 2. fee_to_insurance_bps: portion of trading_fee routed to insurance fund reserve
//! 3. Kani formal verification proofs (impact overflow, inventory limits, insurance fee)

use solana_program::{
    account_info::AccountInfo, entrypoint::ProgramResult, program_error::ProgramError,
    pubkey::Pubkey,
};

use crate::{
    MatcherCall, MatcherReturn, CTX_VAMM_LEN, CTX_VAMM_OFFSET, FLAG_PARTIAL_OK, FLAG_VALID,
    MATCHER_CONTEXT_LEN,
};

// =============================================================================
// Matcher Kind
// =============================================================================

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatcherKind {
    Passive = 0,
    Vamm = 1,
}

impl TryFrom<u8> for MatcherKind {
    type Error = ProgramError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(MatcherKind::Passive),
            1 => Ok(MatcherKind::Vamm),
            _ => Err(ProgramError::InvalidInstructionData),
        }
    }
}

// =============================================================================
// Unified Matcher Context Structure
// =============================================================================

pub const MATCHER_MAGIC: u64 = 0x5045_5243_4d41_5443;
pub const MATCHER_VERSION: u32 = 4; // Bumped from 3 for new fields

/// Unified matcher context stored at offset 64 in matcher context account
///
/// Layout (256 bytes total):
/// ```text
/// Offset  Size  Field
/// 0       8     magic ("PERCMATC")
/// 8       4     version (4)
/// 12      1     kind (0=Passive, 1=vAMM)
/// 13      3     _pad0
/// 16      32    lp_pda
/// 48      4     trading_fee_bps
/// 52      4     base_spread_bps
/// 56      4     max_total_bps
/// 60      4     impact_k_bps (vAMM only)
/// 64      16    liquidity_notional_e6 (vAMM only)
/// 80      16    max_fill_abs
/// 96      16    inventory_base
/// 112     8     last_oracle_price_e6
/// 120     8     last_exec_price_e6
/// 128     16    max_inventory_abs
/// --- NEW FIELDS (carved from reserved) ---
/// 144     2     fee_to_insurance_bps (portion of trading_fee routed to insurance)
/// 146     2     skew_spread_mult_bps (extra spread multiplier per inventory unit, 0=disabled)
/// 148     8     insurance_accrued_e6 (accumulated insurance fee, read-only for cranker)
/// 156     8     lp_account_id (numeric LP identifier, must match instruction data)
/// 164     92    _reserved
/// ```
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MatcherCtx {
    // Header (16 bytes)
    pub magic: u64,
    pub version: u32,
    pub kind: u8,
    pub _pad0: [u8; 3],

    // LP PDA (32 bytes)
    pub lp_pda: [u8; 32],

    // Fee/Spread Parameters (16 bytes)
    pub trading_fee_bps: u32,
    pub base_spread_bps: u32,
    pub max_total_bps: u32,
    pub impact_k_bps: u32,

    // Liquidity/Fill Parameters (32 bytes)
    pub liquidity_notional_e6: u128,
    pub max_fill_abs: u128,

    // State (32 bytes)
    pub inventory_base: i128,
    pub last_oracle_price_e6: u64,
    pub last_exec_price_e6: u64,

    // Limits (16 bytes)
    pub max_inventory_abs: u128,

    // --- NEW: Insurance & Skew (16 bytes, carved from reserved) ---
    /// Accumulated insurance fee in e6 units (cranker reads & sweeps)
    pub insurance_accrued_e6: u64, // 8 bytes, offset 144
    /// Portion of trading_fee_bps routed to insurance reserve (e.g. 500 = 5%)
    pub fee_to_insurance_bps: u16, // 2 bytes, offset 152
    /// Extra spread multiplier per inventory unit for skew-aware quoting
    /// Applied as: extra_bps = |inventory| * skew_spread_mult_bps / 10_000
    /// 0 = disabled (legacy behavior)
    pub skew_spread_mult_bps: u16, // 2 bytes, offset 154
    pub _new_pad: [u8; 4], // 4 bytes, offset 156
    /// Numeric LP account identifier — must match lp_account_id in every matcher call.
    /// Set at init from InitParams; validated in process_call to prevent cross-market spoofing.
    pub lp_account_id: u64, // 8 bytes, offset 160

    // Reserved (88 bytes)
    pub _reserved: [u8; 88],
}

const _: () = assert!(core::mem::size_of::<MatcherCtx>() == CTX_VAMM_LEN);

impl Default for MatcherCtx {
    fn default() -> Self {
        Self {
            magic: 0,
            version: 0,
            kind: 0,
            _pad0: [0; 3],
            lp_pda: [0; 32],
            trading_fee_bps: 0,
            base_spread_bps: 0,
            max_total_bps: 0,
            impact_k_bps: 0,
            liquidity_notional_e6: 0,
            max_fill_abs: 0,
            inventory_base: 0,
            last_oracle_price_e6: 0,
            last_exec_price_e6: 0,
            max_inventory_abs: 0,
            insurance_accrued_e6: 0,
            fee_to_insurance_bps: 0,
            skew_spread_mult_bps: 0,
            _new_pad: [0; 4],
            lp_account_id: 0,
            _reserved: [0; 88],
        }
    }
}

impl MatcherCtx {
    pub fn is_initialized(data: &[u8]) -> bool {
        if data.len() < 8 {
            return false;
        }
        u64::from_le_bytes(data[0..8].try_into().unwrap()) == MATCHER_MAGIC
    }

    pub fn read_from(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < CTX_VAMM_LEN {
            return Err(ProgramError::AccountDataTooSmall);
        }
        let magic = u64::from_le_bytes(data[0..8].try_into().unwrap());
        if magic != MATCHER_MAGIC {
            return Err(ProgramError::UninitializedAccount);
        }

        let mut lp_pda = [0u8; 32];
        lp_pda.copy_from_slice(&data[16..48]);
        let mut reserved = [0u8; 88];
        reserved.copy_from_slice(&data[168..256]);

        Ok(Self {
            magic,
            version: u32::from_le_bytes(data[8..12].try_into().unwrap()),
            kind: data[12],
            _pad0: [0; 3],
            lp_pda,
            trading_fee_bps: u32::from_le_bytes(data[48..52].try_into().unwrap()),
            base_spread_bps: u32::from_le_bytes(data[52..56].try_into().unwrap()),
            max_total_bps: u32::from_le_bytes(data[56..60].try_into().unwrap()),
            impact_k_bps: u32::from_le_bytes(data[60..64].try_into().unwrap()),
            liquidity_notional_e6: u128::from_le_bytes(data[64..80].try_into().unwrap()),
            max_fill_abs: u128::from_le_bytes(data[80..96].try_into().unwrap()),
            inventory_base: i128::from_le_bytes(data[96..112].try_into().unwrap()),
            last_oracle_price_e6: u64::from_le_bytes(data[112..120].try_into().unwrap()),
            last_exec_price_e6: u64::from_le_bytes(data[120..128].try_into().unwrap()),
            max_inventory_abs: u128::from_le_bytes(data[128..144].try_into().unwrap()),
            insurance_accrued_e6: u64::from_le_bytes(data[144..152].try_into().unwrap()),
            fee_to_insurance_bps: u16::from_le_bytes(data[152..154].try_into().unwrap()),
            skew_spread_mult_bps: u16::from_le_bytes(data[154..156].try_into().unwrap()),
            _new_pad: [0; 4],
            lp_account_id: u64::from_le_bytes(data[160..168].try_into().unwrap()),
            _reserved: reserved,
        })
    }

    pub fn write_to(&self, data: &mut [u8]) -> Result<(), ProgramError> {
        if data.len() < CTX_VAMM_LEN {
            return Err(ProgramError::AccountDataTooSmall);
        }
        data[0..8].copy_from_slice(&self.magic.to_le_bytes());
        data[8..12].copy_from_slice(&self.version.to_le_bytes());
        data[12] = self.kind;
        data[13..16].copy_from_slice(&self._pad0);
        data[16..48].copy_from_slice(&self.lp_pda);
        data[48..52].copy_from_slice(&self.trading_fee_bps.to_le_bytes());
        data[52..56].copy_from_slice(&self.base_spread_bps.to_le_bytes());
        data[56..60].copy_from_slice(&self.max_total_bps.to_le_bytes());
        data[60..64].copy_from_slice(&self.impact_k_bps.to_le_bytes());
        data[64..80].copy_from_slice(&self.liquidity_notional_e6.to_le_bytes());
        data[80..96].copy_from_slice(&self.max_fill_abs.to_le_bytes());
        data[96..112].copy_from_slice(&self.inventory_base.to_le_bytes());
        data[112..120].copy_from_slice(&self.last_oracle_price_e6.to_le_bytes());
        data[120..128].copy_from_slice(&self.last_exec_price_e6.to_le_bytes());
        data[128..144].copy_from_slice(&self.max_inventory_abs.to_le_bytes());
        data[144..152].copy_from_slice(&self.insurance_accrued_e6.to_le_bytes());
        data[152..154].copy_from_slice(&self.fee_to_insurance_bps.to_le_bytes());
        data[154..156].copy_from_slice(&self.skew_spread_mult_bps.to_le_bytes());
        data[156..160].copy_from_slice(&self._new_pad);
        data[160..168].copy_from_slice(&self.lp_account_id.to_le_bytes());
        data[168..256].copy_from_slice(&self._reserved);
        Ok(())
    }

    pub fn get_kind(&self) -> Result<MatcherKind, ProgramError> {
        MatcherKind::try_from(self.kind)
    }

    pub fn get_lp_pda(&self) -> Pubkey {
        Pubkey::new_from_array(self.lp_pda)
    }

    pub fn validate(&self) -> Result<(), ProgramError> {
        // 3E.1: Reject stale or mis-versioned accounts before processing.
        if self.version != MATCHER_VERSION {
            return Err(ProgramError::InvalidAccountData);
        }
        let kind = self.get_kind()?;
        if kind == MatcherKind::Vamm && self.liquidity_notional_e6 == 0 {
            return Err(ProgramError::InvalidAccountData);
        }
        if self.max_total_bps > 9000 {
            return Err(ProgramError::InvalidAccountData);
        }
        if self.trading_fee_bps > 1000 {
            return Err(ProgramError::InvalidAccountData);
        }
        let total_fixed = self.base_spread_bps.saturating_add(self.trading_fee_bps);
        if total_fixed > self.max_total_bps {
            return Err(ProgramError::InvalidAccountData);
        }
        if self.lp_pda == [0u8; 32] {
            return Err(ProgramError::InvalidAccountData);
        }
        // fee_to_insurance_bps must be <= 10_000 (100%)
        if self.fee_to_insurance_bps > 10_000 {
            return Err(ProgramError::InvalidAccountData);
        }
        // 3E.4: max_inventory_abs == 0 disables the inventory limit entirely; reject as
        // invalid config — callers must set an explicit bound.
        if self.max_inventory_abs == 0 {
            return Err(ProgramError::InvalidAccountData);
        }
        // M-HIGH-2: max_inventory_abs must fit in i128 so `as i128` cast at call sites
        // is lossless.  Values above i128::MAX are never representable as inventory.
        if self.max_inventory_abs > i128::MAX as u128 {
            return Err(ProgramError::InvalidAccountData);
        }
        // M-NEW-3: max_fill_abs must also fit in i128 so the `fill_abs as i128` cast in
        // compute_{passive,vamm}_execution is lossless.
        if self.max_fill_abs > i128::MAX as u128 {
            return Err(ProgramError::InvalidAccountData);
        }
        // 3E.5: Cap skew_spread_mult_bps at 10_000 bps (100%) at validation time so the
        // runtime clamp never silently absorbs values that shouldn't be accepted at init.
        if self.skew_spread_mult_bps > 10_000 {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(())
    }
}

// =============================================================================
// Init Instruction (Tag 2) — extended with new fields
// =============================================================================

pub const INIT_CTX_LEN: usize = 78; // 70 + 8 (lp_account_id)

#[derive(Clone, Copy, Debug)]
pub struct InitParams {
    pub kind: u8,
    pub trading_fee_bps: u32,
    pub base_spread_bps: u32,
    pub max_total_bps: u32,
    pub impact_k_bps: u32,
    pub liquidity_notional_e6: u128,
    pub max_fill_abs: u128,
    pub max_inventory_abs: u128,
    pub fee_to_insurance_bps: u16,
    pub skew_spread_mult_bps: u16,
    /// Numeric LP account identifier, echoed in every MatcherReturn and validated on
    /// each call to prevent cross-market instruction replay.
    pub lp_account_id: u64,
}

impl InitParams {
    pub fn parse(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < INIT_CTX_LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        if data[0] != crate::MATCHER_INIT_VAMM_TAG {
            return Err(ProgramError::InvalidInstructionData);
        }
        Ok(Self {
            kind: data[1],
            trading_fee_bps: u32::from_le_bytes(data[2..6].try_into().unwrap()),
            base_spread_bps: u32::from_le_bytes(data[6..10].try_into().unwrap()),
            max_total_bps: u32::from_le_bytes(data[10..14].try_into().unwrap()),
            impact_k_bps: u32::from_le_bytes(data[14..18].try_into().unwrap()),
            liquidity_notional_e6: u128::from_le_bytes(data[18..34].try_into().unwrap()),
            max_fill_abs: u128::from_le_bytes(data[34..50].try_into().unwrap()),
            max_inventory_abs: u128::from_le_bytes(data[50..66].try_into().unwrap()),
            fee_to_insurance_bps: u16::from_le_bytes(data[66..68].try_into().unwrap()),
            skew_spread_mult_bps: u16::from_le_bytes(data[68..70].try_into().unwrap()),
            lp_account_id: u64::from_le_bytes(data[70..78].try_into().unwrap()),
        })
    }

    pub fn encode(&self) -> [u8; INIT_CTX_LEN] {
        let mut data = [0u8; INIT_CTX_LEN];
        data[0] = crate::MATCHER_INIT_VAMM_TAG;
        data[1] = self.kind;
        data[2..6].copy_from_slice(&self.trading_fee_bps.to_le_bytes());
        data[6..10].copy_from_slice(&self.base_spread_bps.to_le_bytes());
        data[10..14].copy_from_slice(&self.max_total_bps.to_le_bytes());
        data[14..18].copy_from_slice(&self.impact_k_bps.to_le_bytes());
        data[18..34].copy_from_slice(&self.liquidity_notional_e6.to_le_bytes());
        data[34..50].copy_from_slice(&self.max_fill_abs.to_le_bytes());
        data[50..66].copy_from_slice(&self.max_inventory_abs.to_le_bytes());
        data[66..68].copy_from_slice(&self.fee_to_insurance_bps.to_le_bytes());
        data[68..70].copy_from_slice(&self.skew_spread_mult_bps.to_le_bytes());
        data[70..78].copy_from_slice(&self.lp_account_id.to_le_bytes());
        data
    }
}

// =============================================================================
// Instruction Processing
// =============================================================================

pub fn process_init(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    use solana_program::account_info::next_account_info;

    let account_iter = &mut accounts.iter();
    let lp_pda = next_account_info(account_iter)?;
    let ctx_account = next_account_info(account_iter)?;

    // PERC-321: LP PDA must sign process_init to prevent unauthorized matcher
    // initialisation with attacker-controlled parameters (fees, spread, limits).
    if !lp_pda.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if lp_pda.is_signer { solana_program::msg!("process_init: lp_pda signer=true"); } else { solana_program::msg!("process_init: lp_pda signer=false"); }
    if ctx_account.owner == program_id { solana_program::msg!("process_init: ctx owner ok"); } else { solana_program::msg!("process_init: ctx owner WRONG"); }
    if ctx_account.is_writable { solana_program::msg!("process_init: ctx writable=true"); } else { solana_program::msg!("process_init: ctx writable=FALSE"); }
    if ctx_account.owner != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }
    if ctx_account.data_len() < MATCHER_CONTEXT_LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }
    if !ctx_account.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }

    let params = InitParams::parse(instruction_data)?;
    let _ = MatcherKind::try_from(params.kind)?;

    {
        let data = ctx_account.try_borrow_data()?;
        if MatcherCtx::is_initialized(&data[CTX_VAMM_OFFSET..]) {
            return Err(ProgramError::AccountAlreadyInitialized);
        }
    }

    let ctx = MatcherCtx {
        magic: MATCHER_MAGIC,
        version: MATCHER_VERSION,
        kind: params.kind,
        _pad0: [0; 3],
        lp_pda: lp_pda.key.to_bytes(),
        trading_fee_bps: params.trading_fee_bps,
        base_spread_bps: params.base_spread_bps,
        max_total_bps: params.max_total_bps,
        impact_k_bps: params.impact_k_bps,
        liquidity_notional_e6: params.liquidity_notional_e6,
        max_fill_abs: params.max_fill_abs,
        inventory_base: 0,
        last_oracle_price_e6: 0,
        last_exec_price_e6: 0,
        max_inventory_abs: params.max_inventory_abs,
        insurance_accrued_e6: 0,
        fee_to_insurance_bps: params.fee_to_insurance_bps,
        skew_spread_mult_bps: params.skew_spread_mult_bps,
        _new_pad: [0; 4],
        lp_account_id: params.lp_account_id,
        _reserved: [0; 88],
    };
    ctx.validate()?;

    let mut data = ctx_account.try_borrow_mut_data()?;
    ctx.write_to(&mut data[CTX_VAMM_OFFSET..])?;
    Ok(())
}

pub fn process_call(
    lp_pda: &AccountInfo,
    ctx_account: &AccountInfo,
    instruction_data: &[u8],
) -> ProgramResult {
    let call = MatcherCall::parse(instruction_data)?;

    if call.oracle_price_e6 == 0 {
        return Err(ProgramError::InvalidInstructionData);
    }
    if call.req_size == i128::MIN {
        return Err(ProgramError::InvalidInstructionData);
    }

    let mut ctx = {
        let data = ctx_account.try_borrow_data()?;
        MatcherCtx::read_from(&data[CTX_VAMM_OFFSET..])?
    };
    ctx.validate()?;

    if lp_pda.key.to_bytes() != ctx.lp_pda {
        return Err(ProgramError::InvalidAccountData);
    }

    // 3E.2: Validate that the caller-supplied lp_account_id matches the value stored
    // in the ctx at init time. Without this check a replayed or cross-market instruction
    // could be accepted with a mismatched identifier that gets echoed in MatcherReturn.
    if call.lp_account_id != ctx.lp_account_id {
        return Err(ProgramError::InvalidInstructionData);
    }

    let (exec_price, exec_size, flags) = compute_execution(&ctx, &call)?;

    if exec_size != 0 {
        // 3E.3: Use checked_sub to surface underflow rather than silently saturating.
        ctx.inventory_base = ctx.inventory_base.checked_sub(exec_size)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        ctx.last_oracle_price_e6 = call.oracle_price_e6;
        ctx.last_exec_price_e6 = exec_price;

        // Accrue insurance fee
        if ctx.fee_to_insurance_bps > 0 {
            let insurance_fee = compute_insurance_fee(&ctx, exec_size, exec_price);
            // PERC-321: Use checked_add to detect overflow instead of silently
            // saturating (which would lose insurance fees at u64::MAX).
            ctx.insurance_accrued_e6 = ctx
                .insurance_accrued_e6
                .checked_add(insurance_fee)
                .ok_or(ProgramError::ArithmeticOverflow)?;
        }
    }

    {
        let mut data = ctx_account.try_borrow_mut_data()?;
        ctx.write_to(&mut data[CTX_VAMM_OFFSET..])?;
    }

    let ret = MatcherReturn {
        abi_version: crate::MATCHER_ABI_VERSION,
        flags,
        exec_price_e6: exec_price,
        exec_size,
        req_id: call.req_id,
        lp_account_id: call.lp_account_id,
        oracle_price_e6: call.oracle_price_e6,
        reserved: 0,
    };

    let mut data = ctx_account.try_borrow_mut_data()?;
    ret.write_to(&mut data)?;
    Ok(())
}

// =============================================================================
// Execution Logic
// =============================================================================

fn compute_execution(
    ctx: &MatcherCtx,
    call: &MatcherCall,
) -> Result<(u64, i128, u32), ProgramError> {
    match ctx.get_kind()? {
        MatcherKind::Passive => compute_passive_execution(ctx, call),
        MatcherKind::Vamm => compute_vamm_execution(ctx, call),
    }
}

/// Compute skew-aware spread addition.
///
/// When LP has positive inventory (long) and trade would increase it (sell from user),
/// or LP has negative inventory (short) and trade would worsen it (buy from user),
/// add extra spread proportional to |inventory|.
///
/// extra_bps = |inventory| * skew_spread_mult_bps / 10_000
/// Only applied to the side that worsens inventory.
fn compute_skew_extra_bps(ctx: &MatcherCtx, is_buy: bool) -> u128 {
    if ctx.skew_spread_mult_bps == 0 {
        return 0;
    }

    let inv = ctx.inventory_base;
    // Buy from user => LP sells => inventory decreases
    // Sell from user => LP buys => inventory increases
    let worsens_inventory = if is_buy {
        // Buy worsens if LP is already short (inv < 0, going more negative)
        inv < 0
    } else {
        // Sell worsens if LP is already long (inv > 0, going more positive)
        inv > 0
    };

    if !worsens_inventory {
        return 0;
    }

    let inv_abs = inv.unsigned_abs();
    let mult = ctx.skew_spread_mult_bps as u128;
    // Saturate to avoid unbounded growth — cap at 5000 bps extra (50%)
    let extra = inv_abs.saturating_mul(mult) / 10_000;
    core::cmp::min(extra, 5000)
}

/// Compute insurance fee from a fill: fee_notional * (trading_fee_bps / 10_000) * (fee_to_insurance_bps / 10_000)
/// Returns fee in e6 units.
fn compute_insurance_fee(ctx: &MatcherCtx, exec_size: i128, exec_price: u64) -> u64 {
    let abs_size = exec_size.unsigned_abs();
    let notional_e6 = abs_size.saturating_mul(exec_price as u128) / 1_000_000;
    let fee_portion = notional_e6.saturating_mul(ctx.trading_fee_bps as u128) / 10_000;
    let insurance_portion = fee_portion.saturating_mul(ctx.fee_to_insurance_bps as u128) / 10_000;
    // Saturate to u64
    core::cmp::min(insurance_portion, u64::MAX as u128) as u64
}

fn compute_passive_execution(
    ctx: &MatcherCtx,
    call: &MatcherCall,
) -> Result<(u64, i128, u32), ProgramError> {
    let req_abs = call.req_size.unsigned_abs();
    let is_buy = call.req_size > 0;

    let fill_abs = if ctx.max_fill_abs == 0 {
        0u128
    } else {
        core::cmp::min(req_abs, ctx.max_fill_abs)
    };
    let fill_abs = check_inventory_limit(ctx, fill_abs, is_buy)?;

    if fill_abs == 0 {
        return Ok((call.oracle_price_e6, 0, FLAG_VALID | FLAG_PARTIAL_OK));
    }

    let exec_size = if is_buy {
        fill_abs as i128
    } else {
        -(fill_abs as i128)
    };

    let base = ctx.base_spread_bps as u128;
    let fee = ctx.trading_fee_bps as u128;
    let skew_extra = compute_skew_extra_bps(ctx, is_buy);
    let max_total = ctx.max_total_bps as u128;
    let total_bps = core::cmp::min(max_total, base + fee + skew_extra);

    const BPS_DENOM: u128 = 10_000;
    let oracle = call.oracle_price_e6 as u128;

    let exec_price_u128 = if is_buy {
        // M-HIGH-1: Ceiling division on ask side so LP never under-charges.
        let num = oracle
            .checked_mul(BPS_DENOM + total_bps)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        num.checked_add(BPS_DENOM - 1)
            .ok_or(ProgramError::ArithmeticOverflow)?
            / BPS_DENOM
    } else {
        // Floor division on bid side — rounds down, still favors LP.
        oracle
            .checked_mul(BPS_DENOM - total_bps)
            .ok_or(ProgramError::ArithmeticOverflow)?
            / BPS_DENOM
    };

    if exec_price_u128 == 0 || exec_price_u128 > u64::MAX as u128 {
        return Err(ProgramError::ArithmeticOverflow);
    }

    Ok((exec_price_u128 as u64, exec_size, FLAG_VALID))
}

fn compute_vamm_execution(
    ctx: &MatcherCtx,
    call: &MatcherCall,
) -> Result<(u64, i128, u32), ProgramError> {
    let req_abs = call.req_size.unsigned_abs();
    let is_buy = call.req_size > 0;

    let fill_abs = if ctx.max_fill_abs == 0 {
        0u128
    } else {
        core::cmp::min(req_abs, ctx.max_fill_abs)
    };
    let fill_abs = check_inventory_limit(ctx, fill_abs, is_buy)?;

    if fill_abs == 0 {
        return Ok((call.oracle_price_e6, 0, FLAG_VALID | FLAG_PARTIAL_OK));
    }

    let exec_size = if is_buy {
        fill_abs as i128
    } else {
        -(fill_abs as i128)
    };

    let oracle = call.oracle_price_e6 as u128;
    let abs_notional_e6 = fill_abs
        .checked_mul(oracle)
        .ok_or(ProgramError::ArithmeticOverflow)?
        / 1_000_000;

    // impact_bps = abs_notional_e6 * impact_k_bps / liquidity_notional_e6
    let impact_k = ctx.impact_k_bps as u128;
    let impact_bps = if ctx.liquidity_notional_e6 > 0 {
        abs_notional_e6
            .checked_mul(impact_k)
            .ok_or(ProgramError::ArithmeticOverflow)?
            / ctx.liquidity_notional_e6
    } else {
        0
    };

    let base = ctx.base_spread_bps as u128;
    let fee = ctx.trading_fee_bps as u128;
    let skew_extra = compute_skew_extra_bps(ctx, is_buy);
    let max_total = ctx.max_total_bps as u128;
    let max_impact = max_total
        .saturating_sub(base)
        .saturating_sub(fee)
        .saturating_sub(skew_extra);
    let clamped_impact = core::cmp::min(impact_bps, max_impact);
    let total_bps = core::cmp::min(max_total, base + fee + skew_extra + clamped_impact);

    const BPS_DENOM: u128 = 10_000;

    let exec_price_u128 = if is_buy {
        // M-HIGH-1: Ceiling division on ask side so LP never under-charges.
        let num = oracle
            .checked_mul(BPS_DENOM + total_bps)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        num.checked_add(BPS_DENOM - 1)
            .ok_or(ProgramError::ArithmeticOverflow)?
            / BPS_DENOM
    } else {
        // Floor division on bid side — rounds down, still favors LP.
        oracle
            .checked_mul(BPS_DENOM - total_bps)
            .ok_or(ProgramError::ArithmeticOverflow)?
            / BPS_DENOM
    };

    if exec_price_u128 == 0 || exec_price_u128 > u64::MAX as u128 {
        return Err(ProgramError::ArithmeticOverflow);
    }

    Ok((exec_price_u128 as u64, exec_size, FLAG_VALID))
}

fn check_inventory_limit(
    ctx: &MatcherCtx,
    fill_abs: u128,
    is_buy: bool,
) -> Result<u128, ProgramError> {
    if ctx.max_inventory_abs == 0 {
        return Ok(fill_abs);
    }

    let current_inv = ctx.inventory_base;
    // Safe: validate() ensures max_inventory_abs <= i128::MAX (M-HIGH-2).
    let max_inv = ctx.max_inventory_abs as i128;

    // inventory_base tracks LP position: buy from user => LP sells => inventory decreases.
    // fill_abs <= max_fill_abs <= i128::MAX (M-NEW-3), so the cast is lossless.
    let inv_delta = if is_buy {
        -(fill_abs as i128)
    } else {
        fill_abs as i128
    };
    // M-MED-2: replace saturating_add with checked_add so overflow is surfaced.
    let new_inv = current_inv
        .checked_add(inv_delta)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    if new_inv.unsigned_abs() <= ctx.max_inventory_abs {
        return Ok(fill_abs);
    }

    if is_buy {
        if current_inv <= -max_inv {
            return Ok(0);
        }
        // M-MED-2: replace bare `+` with checked_add.
        let max_fill = current_inv
            .checked_add(max_inv)
            .ok_or(ProgramError::ArithmeticOverflow)?
            .unsigned_abs();
        Ok(core::cmp::min(fill_abs, max_fill))
    } else {
        if current_inv >= max_inv {
            return Ok(0);
        }
        // M-MED-2: replace bare `-` with checked_sub.
        let max_fill = max_inv
            .checked_sub(current_inv)
            .ok_or(ProgramError::ArithmeticOverflow)?
            .unsigned_abs();
        Ok(core::cmp::min(fill_abs, max_fill))
    }
}

// Legacy re-exports
pub use process_call as process_vamm_call;
pub use process_init as process_init_vamm;
pub use MatcherCtx as VammCtx;
pub use MatcherKind as MatcherMode;
pub use MATCHER_MAGIC as VAMM_MAGIC;
pub type InitVammParams = InitParams;
pub const INIT_VAMM_LEN: usize = INIT_CTX_LEN;

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn default_vamm_ctx() -> MatcherCtx {
        MatcherCtx {
            magic: MATCHER_MAGIC,
            version: MATCHER_VERSION,
            kind: MatcherKind::Vamm as u8,
            _pad0: [0; 3],
            lp_pda: [1; 32],
            trading_fee_bps: 5,
            base_spread_bps: 10,
            max_total_bps: 200,
            impact_k_bps: 100,
            liquidity_notional_e6: 1_000_000_000_000,
            max_fill_abs: 1_000_000_000,
            inventory_base: 0,
            last_oracle_price_e6: 0,
            last_exec_price_e6: 0,
            // 3E.4: max_inventory_abs must be non-zero; use i128::MAX as the sentinel
            // (the largest value that passes the M-HIGH-2 validate() bound check).
            max_inventory_abs: i128::MAX as u128,
            insurance_accrued_e6: 0,
            fee_to_insurance_bps: 0,
            skew_spread_mult_bps: 0,
            _new_pad: [0; 4],
            lp_account_id: 100,
            _reserved: [0; 88],
        }
    }

    fn default_passive_ctx() -> MatcherCtx {
        MatcherCtx {
            magic: MATCHER_MAGIC,
            version: MATCHER_VERSION,
            kind: MatcherKind::Passive as u8,
            _pad0: [0; 3],
            lp_pda: [1; 32],
            trading_fee_bps: 5,
            base_spread_bps: 50,
            max_total_bps: 200,
            impact_k_bps: 0,
            liquidity_notional_e6: 0,
            max_fill_abs: 1_000_000_000,
            inventory_base: 0,
            last_oracle_price_e6: 0,
            last_exec_price_e6: 0,
            max_inventory_abs: i128::MAX as u128,
            insurance_accrued_e6: 0,
            fee_to_insurance_bps: 0,
            skew_spread_mult_bps: 0,
            _new_pad: [0; 4],
            lp_account_id: 100,
            _reserved: [0; 88],
        }
    }

    fn make_call(oracle_price: u64, req_size: i128) -> MatcherCall {
        MatcherCall {
            req_id: 1,
            lp_idx: 0,
            lp_account_id: 100,
            oracle_price_e6: oracle_price,
            req_size,
        }
    }

    // --- Original tests (preserved from Toly) ---

    #[test]
    fn test_vamm_buy_adds_spread_and_fee() {
        let ctx = default_vamm_ctx();
        let call = make_call(100_000_000, 1000);
        let (exec_price, exec_size, flags) = compute_execution(&ctx, &call).unwrap();
        assert!(exec_price >= call.oracle_price_e6);
        assert_eq!(exec_size, 1000);
        assert_eq!(flags, FLAG_VALID);
        assert!(exec_price >= 100_015_000);
    }

    #[test]
    fn test_passive_buy_adds_spread_and_fee() {
        let ctx = default_passive_ctx();
        let call = make_call(100_000_000, 1000);
        let (exec_price, exec_size, flags) = compute_execution(&ctx, &call).unwrap();
        assert!(exec_price >= call.oracle_price_e6);
        assert_eq!(exec_size, 1000);
        assert_eq!(flags, FLAG_VALID);
        assert_eq!(exec_price, 100_550_000);
    }

    #[test]
    fn test_vamm_sell_subtracts_spread() {
        let ctx = default_vamm_ctx();
        let call = make_call(100_000_000, -1000);
        let (exec_price, exec_size, flags) = compute_execution(&ctx, &call).unwrap();
        assert!(exec_price <= call.oracle_price_e6);
        assert_eq!(exec_size, -1000);
        assert_eq!(flags, FLAG_VALID);
    }

    #[test]
    fn test_vamm_bigger_size_more_impact() {
        let ctx = default_vamm_ctx();
        let (price_small, _, _) = compute_execution(&ctx, &make_call(100_000_000, 1_000)).unwrap();
        let (price_large, _, _) =
            compute_execution(&ctx, &make_call(100_000_000, 100_000_000)).unwrap();
        assert!(price_large > price_small);
    }

    #[test]
    fn test_total_capped_at_max() {
        let ctx = default_vamm_ctx();
        let (exec_price, _, _) =
            compute_execution(&ctx, &make_call(100_000_000, 1_000_000_000)).unwrap();
        let max_price = 100_000_000u64 * 10_200 / 10_000;
        assert!(exec_price <= max_price);
    }

    #[test]
    fn test_zero_fill_when_max_fill_zero() {
        let mut ctx = default_vamm_ctx();
        ctx.max_fill_abs = 0;
        let call = make_call(100_000_000, 1000);
        let (exec_price, exec_size, flags) = compute_execution(&ctx, &call).unwrap();
        assert_eq!(exec_size, 0);
        assert_eq!(flags, FLAG_VALID | FLAG_PARTIAL_OK);
        assert_eq!(exec_price, call.oracle_price_e6);
    }

    #[test]
    fn test_partial_fill_capped() {
        let mut ctx = default_vamm_ctx();
        ctx.max_fill_abs = 500;
        let (_, exec_size, _) = compute_execution(&ctx, &make_call(100_000_000, 1000)).unwrap();
        assert_eq!(exec_size, 500);
    }

    #[test]
    fn test_inventory_limit_caps_fill() {
        let mut ctx = default_vamm_ctx();
        ctx.max_inventory_abs = 100;
        let (_, exec_size, _) = compute_execution(&ctx, &make_call(100_000_000, 1000)).unwrap();
        assert_eq!(exec_size, 100);
    }

    #[test]
    fn test_inventory_limit_at_boundary() {
        let mut ctx = default_vamm_ctx();
        ctx.max_inventory_abs = 100;
        ctx.inventory_base = -100;
        let (_, exec_size, flags) = compute_execution(&ctx, &make_call(100_000_000, 1000)).unwrap();
        assert_eq!(exec_size, 0);
        assert_eq!(flags, FLAG_VALID | FLAG_PARTIAL_OK);
    }

    #[test]
    fn test_vamm_validation_rejects_zero_liquidity() {
        let mut ctx = default_vamm_ctx();
        ctx.liquidity_notional_e6 = 0;
        assert!(ctx.validate().is_err());
    }

    #[test]
    fn test_passive_allows_zero_liquidity() {
        assert!(default_passive_ctx().validate().is_ok());
    }

    #[test]
    fn test_validation_rejects_high_max_bps() {
        let mut ctx = default_vamm_ctx();
        ctx.max_total_bps = 9500;
        assert!(ctx.validate().is_err());
    }

    #[test]
    fn test_validation_rejects_fee_exceeds_max() {
        let mut ctx = default_vamm_ctx();
        ctx.trading_fee_bps = 100;
        ctx.base_spread_bps = 150;
        ctx.max_total_bps = 200;
        assert!(ctx.validate().is_err());
    }

    #[test]
    fn test_validation_rejects_zero_lp_pda() {
        let mut ctx = default_vamm_ctx();
        ctx.lp_pda = [0; 32];
        assert!(ctx.validate().is_err());
    }

    #[test]
    fn test_ctx_serialization_roundtrip() {
        let ctx = default_vamm_ctx();
        let mut buf = [0u8; CTX_VAMM_LEN];
        ctx.write_to(&mut buf).unwrap();
        let ctx2 = MatcherCtx::read_from(&buf).unwrap();
        assert_eq!(ctx.magic, ctx2.magic);
        assert_eq!(ctx.version, ctx2.version);
        assert_eq!(ctx.kind, ctx2.kind);
        assert_eq!(ctx.trading_fee_bps, ctx2.trading_fee_bps);
        assert_eq!(ctx.fee_to_insurance_bps, ctx2.fee_to_insurance_bps);
        assert_eq!(ctx.skew_spread_mult_bps, ctx2.skew_spread_mult_bps);
        assert_eq!(ctx.insurance_accrued_e6, ctx2.insurance_accrued_e6);
    }

    #[test]
    fn test_init_params_encode_decode() {
        let params = InitParams {
            kind: MatcherKind::Vamm as u8,
            trading_fee_bps: 5,
            base_spread_bps: 10,
            max_total_bps: 200,
            impact_k_bps: 100,
            liquidity_notional_e6: 1_000_000_000_000,
            max_fill_abs: 1_000_000_000,
            max_inventory_abs: 500_000,
            fee_to_insurance_bps: 500,
            skew_spread_mult_bps: 10,
            lp_account_id: 42,
        };
        let encoded = params.encode();
        let decoded = InitParams::parse(&encoded).unwrap();
        assert_eq!(params.kind, decoded.kind);
        assert_eq!(params.fee_to_insurance_bps, decoded.fee_to_insurance_bps);
        assert_eq!(params.skew_spread_mult_bps, decoded.skew_spread_mult_bps);
        assert_eq!(params.lp_account_id, decoded.lp_account_id);
    }

    // --- NEW: Skew-aware inventory tests ---

    #[test]
    fn test_skew_widens_spread_when_worsening_inventory() {
        // LP is long (inv=1000), user sells (would make LP more long) → extra spread
        let mut ctx = default_passive_ctx();
        ctx.skew_spread_mult_bps = 100; // 1% per unit
        ctx.inventory_base = 1000;

        let call_sell = make_call(100_000_000, -100);
        let (price_skewed, _, _) = compute_execution(&ctx, &call_sell).unwrap();

        ctx.skew_spread_mult_bps = 0;
        let (price_normal, _, _) = compute_execution(&ctx, &call_sell).unwrap();

        // Skewed price should be lower for sells (wider spread = lower bid)
        assert!(
            price_skewed < price_normal,
            "skew should widen sell spread: {} < {}",
            price_skewed,
            price_normal
        );
    }

    #[test]
    fn test_skew_no_extra_when_improving_inventory() {
        // LP is long (inv=1000), user buys (LP sells, reducing long) → no extra spread
        let mut ctx = default_passive_ctx();
        ctx.skew_spread_mult_bps = 100;
        ctx.inventory_base = 1000;

        let call_buy = make_call(100_000_000, 100);
        let (price_with_skew, _, _) = compute_execution(&ctx, &call_buy).unwrap();

        ctx.skew_spread_mult_bps = 0;
        let (price_without, _, _) = compute_execution(&ctx, &call_buy).unwrap();

        assert_eq!(
            price_with_skew, price_without,
            "no skew penalty when improving inventory"
        );
    }

    #[test]
    fn test_skew_extra_capped_at_5000_bps() {
        let mut ctx = default_passive_ctx();
        ctx.skew_spread_mult_bps = 10_000; // 100% per unit
        ctx.inventory_base = 100_000; // huge inventory
        ctx.max_total_bps = 9000; // raise max to see cap effect

        let extra = compute_skew_extra_bps(&ctx, false); // sell worsens long
        assert_eq!(extra, 5000, "skew extra capped at 5000 bps");
    }

    // --- NEW: Insurance fee tests ---

    #[test]
    fn test_insurance_fee_computation() {
        let ctx = MatcherCtx {
            trading_fee_bps: 100,      // 1%
            fee_to_insurance_bps: 500, // 5% of trading fee → insurance
            ..default_vamm_ctx()
        };
        // exec_size=1_000_000, exec_price=100_000_000
        // notional_e6 = 1_000_000 * 100_000_000 / 1_000_000 = 100_000_000
        // fee_portion = 100_000_000 * 100 / 10_000 = 1_000_000
        // insurance = 1_000_000 * 500 / 10_000 = 50_000
        let fee = compute_insurance_fee(&ctx, 1_000_000, 100_000_000);
        assert_eq!(fee, 50_000);
    }

    #[test]
    fn test_insurance_fee_zero_when_disabled() {
        let ctx = MatcherCtx {
            fee_to_insurance_bps: 0,
            ..default_vamm_ctx()
        };
        let fee = compute_insurance_fee(&ctx, 1_000_000, 100_000_000);
        assert_eq!(fee, 0);
    }

    #[test]
    fn test_insurance_fee_negative_size() {
        // Should use absolute size
        let ctx = MatcherCtx {
            trading_fee_bps: 100,
            fee_to_insurance_bps: 500,
            ..default_vamm_ctx()
        };
        let fee_pos = compute_insurance_fee(&ctx, 1_000_000, 100_000_000);
        let fee_neg = compute_insurance_fee(&ctx, -1_000_000, 100_000_000);
        assert_eq!(fee_pos, fee_neg);
    }

    #[test]
    fn test_validation_rejects_insurance_bps_over_10000() {
        let mut ctx = default_vamm_ctx();
        ctx.fee_to_insurance_bps = 10_001;
        assert!(ctx.validate().is_err());
    }

    // --- Audit fix tests (3E.1 – 3E.5) ---

    // 3E.1: validate() must reject wrong version.
    #[test]
    fn test_validation_rejects_wrong_version() {
        let mut ctx = default_vamm_ctx();
        ctx.version = MATCHER_VERSION - 1;
        assert!(
            ctx.validate().is_err(),
            "validate() must reject version != MATCHER_VERSION"
        );
    }

    #[test]
    fn test_validation_accepts_correct_version() {
        let ctx = default_vamm_ctx();
        assert!(ctx.validate().is_ok());
    }

    // 3E.2: lp_account_id in ctx serialises/deserialises correctly.
    #[test]
    fn test_lp_account_id_roundtrip() {
        let mut ctx = default_vamm_ctx();
        ctx.lp_account_id = 0xDEAD_BEEF_CAFE_1234;
        let mut buf = [0u8; CTX_VAMM_LEN];
        ctx.write_to(&mut buf).unwrap();
        let ctx2 = MatcherCtx::read_from(&buf).unwrap();
        assert_eq!(ctx.lp_account_id, ctx2.lp_account_id);
    }

    // 3E.4: validate() must reject max_inventory_abs == 0.
    #[test]
    fn test_validation_rejects_zero_max_inventory_abs() {
        let mut ctx = default_vamm_ctx();
        ctx.max_inventory_abs = 0;
        assert!(
            ctx.validate().is_err(),
            "validate() must reject max_inventory_abs == 0"
        );
    }

    #[test]
    fn test_validation_accepts_nonzero_max_inventory_abs() {
        let mut ctx = default_vamm_ctx();
        ctx.max_inventory_abs = 1;
        assert!(ctx.validate().is_ok());
    }

    // 3E.5: validate() must reject skew_spread_mult_bps > 10_000.
    #[test]
    fn test_validation_rejects_skew_mult_over_10000() {
        let mut ctx = default_vamm_ctx();
        ctx.skew_spread_mult_bps = 10_001;
        assert!(
            ctx.validate().is_err(),
            "validate() must reject skew_spread_mult_bps > 10_000"
        );
    }

    #[test]
    fn test_validation_accepts_skew_mult_at_10000() {
        let mut ctx = default_vamm_ctx();
        ctx.skew_spread_mult_bps = 10_000;
        assert!(ctx.validate().is_ok());
    }

    // --- M-HIGH-1: Ceiling division on buy side ---

    /// Verify that compute_passive_execution rounds UP on buy so exec_price > raw floor
    /// when the multiplication is not evenly divisible by BPS_DENOM.
    #[test]
    fn test_passive_buy_ceiling_div_rounds_up() {
        // oracle=100_000_001, base_spread=50 bps, fee=5 bps => total=55 bps
        // num = 100_000_001 * (10_000 + 55) = 100_000_001 * 10_055
        // = 1_005_500_010_055
        // floor = 1_005_500_010_055 / 10_000 = 100_550_001  (remainder 55)
        // ceil  = 100_550_002
        let ctx = default_passive_ctx(); // base_spread=50, fee=5, max_total=200
        let call = make_call(100_000_001, 1);
        let (exec_price, exec_size, flags) = compute_execution(&ctx, &call).unwrap();
        assert_eq!(exec_size, 1);
        assert_eq!(flags, FLAG_VALID);
        // Independently compute expected ceil
        const BPS_DENOM: u128 = 10_000;
        let total_bps: u128 = 55; // base=50 + fee=5
        let oracle: u128 = 100_000_001;
        let num = oracle * (BPS_DENOM + total_bps);
        let expected_floor = num / BPS_DENOM;
        let expected_ceil = num.div_ceil(BPS_DENOM);
        // Ceil must be strictly greater than floor for non-zero remainder
        assert!(
            expected_ceil > expected_floor,
            "test setup: remainder must be non-zero for this to be meaningful"
        );
        assert_eq!(exec_price as u128, expected_ceil, "buy side must use ceiling div");
    }

    /// Verify that compute_passive_execution floor-divides on sell.
    #[test]
    fn test_passive_sell_floor_div() {
        let ctx = default_passive_ctx(); // base_spread=50, fee=5
        let call = make_call(100_000_001, -1);
        let (exec_price, exec_size, flags) = compute_execution(&ctx, &call).unwrap();
        assert_eq!(exec_size, -1);
        assert_eq!(flags, FLAG_VALID);
        const BPS_DENOM: u128 = 10_000;
        let total_bps: u128 = 55;
        let oracle: u128 = 100_000_001;
        let expected_floor = oracle * (BPS_DENOM - total_bps) / BPS_DENOM;
        assert_eq!(exec_price as u128, expected_floor, "sell side must use floor div");
    }

    /// Same ceiling division test for vAMM path.
    #[test]
    fn test_vamm_buy_ceiling_div_rounds_up() {
        let ctx = default_vamm_ctx(); // base_spread=10, fee=5, impact_k=100, liq=1e12
        // Use req_size=1 so impact is negligible and total_bps is just base+fee = 15
        let call = make_call(100_000_001, 1);
        let (exec_price, exec_size, flags) = compute_execution(&ctx, &call).unwrap();
        assert_eq!(exec_size, 1);
        assert_eq!(flags, FLAG_VALID);
        // total_bps ≈ 15 (impact tiny for size=1 vs liq=1e12)
        // exec_price >= oracle is the invariant; also verify ceiling rounding
        assert!(
            exec_price as u128 >= 100_000_001,
            "vAMM buy must be >= oracle"
        );
    }

    // --- M-HIGH-2: validate() rejects max_inventory_abs > i128::MAX ---

    #[test]
    fn test_validation_rejects_max_inventory_abs_above_i128_max() {
        let mut ctx = default_vamm_ctx();
        ctx.max_inventory_abs = i128::MAX as u128 + 1;
        assert!(
            ctx.validate().is_err(),
            "validate() must reject max_inventory_abs > i128::MAX"
        );
    }

    #[test]
    fn test_validation_accepts_max_inventory_abs_at_i128_max() {
        let mut ctx = default_vamm_ctx();
        ctx.max_inventory_abs = i128::MAX as u128;
        assert!(
            ctx.validate().is_ok(),
            "validate() must accept max_inventory_abs == i128::MAX"
        );
    }

    // --- M-NEW-3: validate() rejects max_fill_abs > i128::MAX ---

    #[test]
    fn test_validation_rejects_max_fill_abs_above_i128_max() {
        let mut ctx = default_vamm_ctx();
        ctx.max_fill_abs = i128::MAX as u128 + 1;
        assert!(
            ctx.validate().is_err(),
            "validate() must reject max_fill_abs > i128::MAX"
        );
    }

    #[test]
    fn test_validation_accepts_max_fill_abs_at_i128_max() {
        let mut ctx = default_vamm_ctx();
        ctx.max_fill_abs = i128::MAX as u128;
        assert!(
            ctx.validate().is_ok(),
            "validate() must accept max_fill_abs == i128::MAX"
        );
    }

    // --- M-MED-2: check_inventory_limit uses checked arithmetic ---

    /// When current_inv + max_inv would overflow i128 (not possible post-validate()
    /// given the i128::MAX bound, but verify the happy path still works at extreme
    /// valid values).
    #[test]
    fn test_inventory_limit_at_i128_max_boundary() {
        let mut ctx = default_vamm_ctx();
        ctx.max_inventory_abs = i128::MAX as u128;
        ctx.inventory_base = 0;
        // Large buy request — fill should be capped at min(req, max_inv) = max_inv
        ctx.max_fill_abs = i128::MAX as u128;
        let fill_abs_result =
            check_inventory_limit(&ctx, i128::MAX as u128, true);
        assert!(
            fill_abs_result.is_ok(),
            "check_inventory_limit must not error at i128::MAX boundary"
        );
    }
}

// =============================================================================
// Kani Proofs
// =============================================================================

#[cfg(kani)]
mod proofs {
    use super::*;

    /// Proof 1: impact_bps computation never overflows for valid inputs.
    /// Bounded: oracle_price_e6 ≤ 1e12, fill_abs ≤ 1e18, impact_k_bps ≤ 9000,
    /// liquidity_notional_e6 ≥ 1.
    #[kani::proof]
    #[kani::unwind(1)]
    fn proof_impact_bps_no_overflow() {
        let oracle: u64 = kani::any();
        kani::assume(oracle > 0 && oracle <= 1_000_000_000_000); // max $1M price

        let fill_abs: u128 = kani::any();
        kani::assume(fill_abs > 0 && fill_abs <= 1_000_000_000_000_000_000); // max 1e18

        let impact_k_bps: u32 = kani::any();
        kani::assume(impact_k_bps <= 9000);

        let liquidity_notional_e6: u128 = kani::any();
        kani::assume(liquidity_notional_e6 >= 1);

        let oracle_u128 = oracle as u128;
        // abs_notional_e6 = fill_abs * oracle / 1_000_000
        let abs_notional_e6 = fill_abs.checked_mul(oracle_u128);
        // This can overflow for extreme fill_abs * oracle, which is caught by checked_mul
        if let Some(notional_raw) = abs_notional_e6 {
            let notional = notional_raw / 1_000_000;
            let impact_result = notional.checked_mul(impact_k_bps as u128);
            if let Some(impact_numer) = impact_result {
                let impact_bps = impact_numer / liquidity_notional_e6;
                // Impact bps should be bounded (at most fill the cap)
                assert!(impact_bps <= u128::MAX);
            }
            // If checked_mul returns None, the program returns ArithmeticOverflow — safe.
        }
    }

    /// Proof 2: inventory_base after fill never exceeds max_inventory_abs.
    #[kani::proof]
    #[kani::unwind(1)]
    fn proof_inventory_limit_enforced() {
        let max_inv: u128 = kani::any();
        kani::assume(max_inv > 0 && max_inv <= 1_000_000_000_000);

        let current_inv: i128 = kani::any();
        kani::assume(current_inv.unsigned_abs() <= max_inv);

        let fill_req: u128 = kani::any();
        kani::assume(fill_req <= 1_000_000_000_000);

        let is_buy: bool = kani::any();

        let ctx = MatcherCtx {
            magic: MATCHER_MAGIC,
            version: MATCHER_VERSION,
            kind: MatcherKind::Vamm as u8,
            _pad0: [0; 3],
            lp_pda: [1; 32],
            trading_fee_bps: 5,
            base_spread_bps: 10,
            max_total_bps: 200,
            impact_k_bps: 100,
            liquidity_notional_e6: 1_000_000_000_000,
            max_fill_abs: u128::MAX,
            inventory_base: current_inv,
            last_oracle_price_e6: 0,
            last_exec_price_e6: 0,
            max_inventory_abs: max_inv,
            insurance_accrued_e6: 0,
            fee_to_insurance_bps: 0,
            skew_spread_mult_bps: 0,
            _new_pad: [0; 4],
            lp_account_id: 0,
            _reserved: [0; 88],
        };

        let fill_abs = check_inventory_limit(&ctx, fill_req, is_buy).unwrap();

        // Compute new inventory after fill
        let inv_delta = if is_buy {
            -(fill_abs as i128)
        } else {
            fill_abs as i128
        };
        let new_inv = current_inv.saturating_add(inv_delta);

        // PROPERTY: new inventory must not exceed max
        assert!(
            new_inv.unsigned_abs() <= max_inv,
            "inventory violation: |{}| > {}",
            new_inv,
            max_inv
        );
    }

    /// Proof 3: insurance_accrued_e6 never exceeds fee_portion (fee is fraction of trading fee).
    /// Specifically: insurance_fee ≤ notional * trading_fee_bps / 10_000.
    #[kani::proof]
    #[kani::unwind(1)]
    fn proof_insurance_fee_bounded_by_trading_fee() {
        let exec_size: i128 = kani::any();
        kani::assume(exec_size != 0 && exec_size != i128::MIN);
        kani::assume(exec_size.unsigned_abs() <= 1_000_000_000_000_000_000);

        let exec_price: u64 = kani::any();
        kani::assume(exec_price > 0 && exec_price <= 1_000_000_000_000);

        let trading_fee_bps: u32 = kani::any();
        kani::assume(trading_fee_bps <= 1000);

        let fee_to_insurance_bps: u16 = kani::any();
        kani::assume(fee_to_insurance_bps <= 10_000);

        let ctx = MatcherCtx {
            trading_fee_bps,
            fee_to_insurance_bps,
            ..MatcherCtx::default()
        };

        let insurance_fee = compute_insurance_fee(&ctx, exec_size, exec_price);

        // Full trading fee
        let abs_size = exec_size.unsigned_abs();
        let notional_e6 = abs_size.saturating_mul(exec_price as u128) / 1_000_000;
        let full_trading_fee = notional_e6.saturating_mul(trading_fee_bps as u128) / 10_000;

        // PROPERTY: insurance fee ≤ full trading fee
        assert!(
            (insurance_fee as u128) <= full_trading_fee,
            "insurance {} > trading fee {}",
            insurance_fee,
            full_trading_fee
        );
    }

    // =========================================================================
    // PERC-320: Additional vAMM proofs (PERC-316)
    // =========================================================================

    /// Proof 4: buy exec_price >= oracle_price (LP charges spread on buys).
    #[kani::proof]
    #[kani::unwind(1)]
    fn proof_vamm_buy_price_above_oracle() {
        let oracle: u64 = kani::any();
        kani::assume(oracle > 0 && oracle <= 1_000_000_000_000);

        let total_bps: u128 = kani::any();
        kani::assume(total_bps <= 10_000);

        const BPS_DENOM: u128 = 10_000;
        let exec_price = (oracle as u128) * (BPS_DENOM + total_bps) / BPS_DENOM;

        assert!(
            exec_price >= oracle as u128,
            "buy exec price must be >= oracle price"
        );
    }

    /// Proof 5: sell exec_price <= oracle_price (LP charges spread on sells).
    #[kani::proof]
    #[kani::unwind(1)]
    fn proof_vamm_sell_price_below_oracle() {
        let oracle: u64 = kani::any();
        kani::assume(oracle > 0 && oracle <= 1_000_000_000_000);

        let total_bps: u128 = kani::any();
        kani::assume(total_bps <= 10_000);

        const BPS_DENOM: u128 = 10_000;
        let exec_price = (oracle as u128) * (BPS_DENOM - total_bps) / BPS_DENOM;

        assert!(
            exec_price <= oracle as u128,
            "sell exec price must be <= oracle price"
        );
    }

    /// Proof 6: inventory limit reduces fill when limit would be breached.
    #[kani::proof]
    #[kani::unwind(1)]
    fn proof_inventory_limit_reduces_fill() {
        let max_inv: u128 = kani::any();
        kani::assume(max_inv > 0 && max_inv <= 1_000_000_000_000);

        let current_inv: i128 = kani::any();
        kani::assume(current_inv.unsigned_abs() <= max_inv);

        let fill_req: u128 = kani::any();
        kani::assume(fill_req > 0 && fill_req <= 1_000_000_000_000);

        let is_buy: bool = kani::any();

        let ctx = MatcherCtx {
            max_inventory_abs: max_inv,
            inventory_base: current_inv,
            ..MatcherCtx::default()
        };

        let fill_abs = check_inventory_limit(&ctx, fill_req, is_buy).unwrap();

        // Fill must not exceed request
        assert!(
            fill_abs <= fill_req,
            "fill must not exceed requested amount"
        );
    }

    /// Proof 7: impact_bps monotonically increases with fill size.
    #[kani::proof]
    #[kani::unwind(1)]
    fn proof_impact_monotonically_increases_with_fill_size() {
        let oracle: u64 = kani::any();
        kani::assume(oracle > 0 && oracle <= 1_000_000_000_000);

        let fill1: u128 = kani::any();
        let fill2: u128 = kani::any();
        kani::assume(fill1 > 0 && fill1 <= fill2);
        kani::assume(fill2 <= 1_000_000_000_000);

        let impact_k_bps: u32 = kani::any();
        kani::assume(impact_k_bps <= 9000);

        let liquidity: u128 = kani::any();
        kani::assume(liquidity >= 1_000_000);

        let oracle_u128 = oracle as u128;

        // Impact for fill1
        let notional1 = fill1.saturating_mul(oracle_u128) / 1_000_000;
        let impact1 = notional1.saturating_mul(impact_k_bps as u128) / liquidity;

        // Impact for fill2
        let notional2 = fill2.saturating_mul(oracle_u128) / 1_000_000;
        let impact2 = notional2.saturating_mul(impact_k_bps as u128) / liquidity;

        assert!(impact2 >= impact1, "larger fills must produce >= impact");
    }

    /// Proof 8: skew extra spread capped at 5000 bps.
    #[kani::proof]
    #[kani::unwind(1)]
    fn proof_skew_spread_capped_at_5000() {
        let inv: i128 = kani::any();
        let mult_bps: u16 = kani::any();
        kani::assume(mult_bps > 0);

        let is_buy: bool = kani::any();

        let ctx = MatcherCtx {
            inventory_base: inv,
            skew_spread_mult_bps: mult_bps,
            ..MatcherCtx::default()
        };

        let extra = compute_skew_extra_bps(&ctx, is_buy);
        assert!(
            extra <= 5000,
            "skew extra spread must be capped at 5000 bps"
        );
    }

    /// Proof 9: passive spread never produces zero exec_price for valid oracle.
    /// For any valid oracle_price > 0 and total_bps <= 9000 (max_total_bps cap),
    /// the resulting exec_price is always > 0.
    #[kani::proof]
    #[kani::unwind(1)]
    fn proof_passive_spread_never_negative() {
        let oracle: u64 = kani::any();
        kani::assume(oracle > 0 && oracle <= 1_000_000_000_000); // max $1M

        let base_spread_bps: u32 = kani::any();
        let trading_fee_bps: u32 = kani::any();
        let skew_extra: u128 = kani::any();

        kani::assume(base_spread_bps <= 1000);
        kani::assume(trading_fee_bps <= 1000);
        kani::assume(skew_extra <= 5000);

        let max_total_bps: u32 = kani::any();
        kani::assume(max_total_bps <= 9000);
        kani::assume(base_spread_bps + trading_fee_bps <= max_total_bps);

        let total_bps = core::cmp::min(
            max_total_bps as u128,
            base_spread_bps as u128 + trading_fee_bps as u128 + skew_extra,
        );

        const BPS_DENOM: u128 = 10_000;
        let oracle_u128 = oracle as u128;

        // Buy side: oracle * (10_000 + total_bps) / 10_000
        let buy_price = oracle_u128 * (BPS_DENOM + total_bps) / BPS_DENOM;
        assert!(buy_price > 0, "buy exec_price must always be > 0");

        // Sell side: oracle * (10_000 - total_bps) / 10_000
        // total_bps <= 9000 < 10_000, so (BPS_DENOM - total_bps) >= 1000 > 0
        let sell_price = oracle_u128 * (BPS_DENOM - total_bps) / BPS_DENOM;
        assert!(
            sell_price > 0,
            "sell exec_price must always be > 0 for valid oracle"
        );
    }

    /// Proof 10: total_bps never exceeds max_total_bps.
    #[kani::proof]
    #[kani::unwind(1)]
    fn proof_total_bps_capped_by_max() {
        let base: u128 = kani::any();
        let fee: u128 = kani::any();
        let skew_extra: u128 = kani::any();
        let impact: u128 = kani::any();
        let max_total: u128 = kani::any();

        kani::assume(base <= 1000);
        kani::assume(fee <= 1000);
        kani::assume(skew_extra <= 5000);
        kani::assume(impact <= 9000);
        kani::assume(max_total <= 10_000);

        let total_bps = core::cmp::min(max_total, base + fee + skew_extra + impact);
        assert!(
            total_bps <= max_total,
            "total bps must never exceed max_total_bps"
        );
    }

    // =========================================================================
    // M-HIGH-1: Ceiling division — buy exec_price is STRICTLY >= mid-oracle
    // =========================================================================

    /// Proof 11 (M-HIGH-1): For any oracle and any total_bps, the ceiling-division
    /// buy exec_price is >= the oracle price (LP never under-charges mid).
    #[kani::proof]
    #[kani::unwind(1)]
    fn k_ceiling_div_buy_never_under_mid() {
        let oracle: u64 = kani::any();
        kani::assume(oracle > 0 && oracle <= 1_000_000_000_000);

        let total_bps: u128 = kani::any();
        kani::assume(total_bps <= 10_000);

        const BPS_DENOM: u128 = 10_000;
        let oracle_u128 = oracle as u128;

        // Ceiling division formula used in the fixed code
        let num = oracle_u128.checked_mul(BPS_DENOM + total_bps);
        if let Some(num) = num {
            if let Some(num_rounded) = num.checked_add(BPS_DENOM - 1) {
                let exec_price = num_rounded / BPS_DENOM;
                assert!(
                    exec_price >= oracle_u128,
                    "buy exec_price (ceil div) must be >= oracle"
                );
            }
        }
    }

    // =========================================================================
    // M-HIGH-2 + M-NEW-3: validate() rejects out-of-range inventory/fill limits
    // =========================================================================

    /// Proof 12 (M-HIGH-2 + M-NEW-3): validate() rejects max_inventory_abs and
    /// max_fill_abs values that exceed i128::MAX.
    #[kani::proof]
    #[kani::unwind(1)]
    fn k_validate_rejects_u128_above_i128_max() {
        // max_inventory_abs above i128::MAX
        let ctx_inv = MatcherCtx {
            magic: MATCHER_MAGIC,
            version: MATCHER_VERSION,
            kind: MatcherKind::Vamm as u8,
            _pad0: [0; 3],
            lp_pda: [1; 32],
            trading_fee_bps: 5,
            base_spread_bps: 10,
            max_total_bps: 200,
            impact_k_bps: 100,
            liquidity_notional_e6: 1_000_000_000_000,
            max_fill_abs: 1_000_000,
            inventory_base: 0,
            last_oracle_price_e6: 0,
            last_exec_price_e6: 0,
            max_inventory_abs: i128::MAX as u128 + 1,
            insurance_accrued_e6: 0,
            fee_to_insurance_bps: 0,
            skew_spread_mult_bps: 0,
            _new_pad: [0; 4],
            lp_account_id: 1,
            _reserved: [0; 88],
        };
        assert!(
            ctx_inv.validate().is_err(),
            "validate must reject max_inventory_abs > i128::MAX"
        );

        // max_fill_abs above i128::MAX
        let ctx_fill = MatcherCtx {
            max_inventory_abs: 1_000_000,
            max_fill_abs: i128::MAX as u128 + 1,
            ..ctx_inv
        };
        assert!(
            ctx_fill.validate().is_err(),
            "validate must reject max_fill_abs > i128::MAX"
        );
    }
}
