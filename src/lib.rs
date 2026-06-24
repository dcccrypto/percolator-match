#![no_std]

extern crate alloc;

pub mod passive_lp_matcher;
pub mod vamm;

pub use passive_lp_matcher::*;
pub use vamm::*;

use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    program_error::ProgramError,
    pubkey::Pubkey,
};

// =============================================================================
// Context Account Layout
// =============================================================================
// Bytes 0-63:   Matcher return data (64 bytes, written on each call) - ABI required
// Bytes 64-319: MatcherCtx state (256 bytes)
// Total: 320 bytes

/// Offset where matcher return is written (must be 0 per ABI)
pub const CTX_RETURN_OFFSET: usize = 0;
/// Length of matcher return (64 bytes per ABI)
pub const MATCHER_RETURN_LEN: usize = 64;
/// Offset where matcher context state begins
pub const CTX_VAMM_OFFSET: usize = MATCHER_RETURN_LEN; // 64
/// Length of matcher context state
pub const CTX_VAMM_LEN: usize = 256;
/// Minimum context account size
pub const MATCHER_CONTEXT_LEN: usize = 320;

// =============================================================================
// Instruction Tags
// =============================================================================

/// Matcher call instruction tag (from percolator CPI)
pub const MATCHER_CALL_TAG: u8 = 0;
/// Initialize context instruction tag
pub const MATCHER_INIT_VAMM_TAG: u8 = 2;
/// Batched matcher call instruction tag (atomic multi-leg CPI from percolator).
pub const MATCHER_BATCH_CALL_TAG: u8 = 3;

// =============================================================================
// Batched Matcher Call Layout (tag 3) - one LP fills N legs in a single CPI
// =============================================================================
/// Offset  Field            Type     Size
/// 0       tag              u8       1      Always 3
/// 1       n                u8       1      leg count (1..=MATCHER_BATCH_MAX_LEGS)
/// 2-10    req_id           u64      8      batch-level request id
/// 10-18   lp_account_id    u64      8      single LP, echoed on every leg
/// 18..    legs[n]: { asset_index u16, oracle_price_e6 u64, req_size i128 }  (26 bytes each)
///
/// Returns N back-to-back MatcherReturn (64 bytes each) via sol_set_return_data — the per-leg
/// returns can't be written into the context account (its return slot is only 64 bytes and the
/// context state follows immediately), and N*64 fits Solana's 1024-byte return-data cap for N<=16.
pub const MATCHER_BATCH_HEADER_LEN: usize = 18;
pub const MATCHER_BATCH_LEG_LEN: usize = 26;
pub const MATCHER_BATCH_MAX_LEGS: usize = 16;

// =============================================================================
// Matcher Call Layout (67 bytes) - Tag 0
// =============================================================================
pub const MATCHER_CALL_LEN: usize = 67;

// =============================================================================
// Matcher Return Layout (64 bytes)
// =============================================================================

pub const FLAG_VALID: u32 = 1;
pub const FLAG_PARTIAL_OK: u32 = 2;
pub const FLAG_REJECTED: u32 = 4;
pub const MATCHER_ABI_VERSION: u32 = 3;

// =============================================================================
// Oracle Price Validation Constants
// =============================================================================

/// Upper sanity ceiling for a caller-supplied `oracle_price_e6`.
///
/// Prices are denominated in 1e-6 USD (i.e., a $1.00 asset is 1_000_000). The
/// largest plausible real-world perp asset is ~$1 000 000 per unit, which is
/// 1_000_000_000_000 (1e12) in E6. This ceiling is 1_000× that (1e15), leaving
/// ample room for any extreme-price asset while still catching obviously-corrupt
/// or adversarially-crafted inputs (e.g., u64::MAX ≈ 1.8e19). Any single E6
/// price above 1e15 would correspond to a per-unit value > $1 billion — an input
/// that cannot be a legitimate price quote from any real market.
///
/// This constant is intentionally conservative: it does NOT constrain the market;
/// it only rejects inputs that are structurally impossible.
pub const ORACLE_PRICE_E6_MAX: u64 = 1_000_000_000_000_000; // 1e15 in E6 = $1B per unit

/// `ProgramError::Custom` discriminant for a batch call where the same
/// `asset_index` appears in more than one leg with different `oracle_price_e6`
/// values. A legitimate caller (percolator-prog) reads all asset prices from one
/// atomic snapshot so legs on the same asset are always byte-identical.
/// Discriminant chosen to be distinct from all existing Custom codes used by the
/// wrapper (up through Custom(41) as of v16-lp-vault-complete).
pub const ERR_INCONSISTENT_LEG_ORACLE_PRICE: u32 = 8001;

/// Matcher return structure written to context account at offset 0
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct MatcherReturn {
    pub abi_version: u32,
    pub flags: u32,
    pub exec_price_e6: u64,
    pub exec_size: i128,
    pub req_id: u64,
    pub lp_account_id: u64,
    pub oracle_price_e6: u64,
    /// v3: echo of the call's asset_index (bytes 9-11 of MatcherCall), stored
    /// as u64 for fixed-offset compatibility. Replaces v2's `reserved: u64`.
    pub asset_index: u64,
}

impl MatcherReturn {
    pub fn write_to(&self, data: &mut [u8]) -> Result<(), ProgramError> {
        if data.len() < MATCHER_RETURN_LEN {
            return Err(ProgramError::AccountDataTooSmall);
        }
        data[0..4].copy_from_slice(&self.abi_version.to_le_bytes());
        data[4..8].copy_from_slice(&self.flags.to_le_bytes());
        data[8..16].copy_from_slice(&self.exec_price_e6.to_le_bytes());
        data[16..32].copy_from_slice(&self.exec_size.to_le_bytes());
        data[32..40].copy_from_slice(&self.req_id.to_le_bytes());
        data[40..48].copy_from_slice(&self.lp_account_id.to_le_bytes());
        data[48..56].copy_from_slice(&self.oracle_price_e6.to_le_bytes());
        data[56..64].copy_from_slice(&self.asset_index.to_le_bytes());
        Ok(())
    }

    pub fn rejected(
        req_id: u64,
        lp_account_id: u64,
        asset_index: u16,
        oracle_price_e6: u64,
    ) -> Self {
        Self {
            abi_version: MATCHER_ABI_VERSION,
            flags: FLAG_VALID | FLAG_REJECTED,
            exec_price_e6: 1,
            exec_size: 0,
            req_id,
            lp_account_id,
            oracle_price_e6,
            asset_index: asset_index as u64,
        }
    }

    pub fn filled(
        exec_price: u64,
        exec_size: i128,
        req_id: u64,
        lp_account_id: u64,
        asset_index: u16,
        oracle_price_e6: u64,
    ) -> Self {
        Self {
            abi_version: MATCHER_ABI_VERSION,
            flags: FLAG_VALID,
            exec_price_e6: exec_price,
            exec_size,
            req_id,
            lp_account_id,
            oracle_price_e6,
            asset_index: asset_index as u64,
        }
    }

    pub fn zero_fill(
        req_id: u64,
        lp_account_id: u64,
        asset_index: u16,
        oracle_price_e6: u64,
    ) -> Self {
        Self {
            abi_version: MATCHER_ABI_VERSION,
            flags: FLAG_VALID | FLAG_PARTIAL_OK,
            exec_price_e6: 1,
            exec_size: 0,
            req_id,
            lp_account_id,
            oracle_price_e6,
            asset_index: asset_index as u64,
        }
    }
}

/// Parsed matcher call from instruction data
#[derive(Clone, Copy, Debug)]
pub struct MatcherCall {
    pub req_id: u64,
    /// v3 (was `lp_idx`): asset slot index in the wrapper's MarketGroup that
    /// this matcher call targets. Wire bytes 9-11 unchanged from v2; only the
    /// field name is corrected to match v3 ABI semantics. Echoed back in
    /// MatcherReturn.asset_index.
    pub asset_index: u16,
    pub lp_account_id: u64,
    pub oracle_price_e6: u64,
    pub req_size: i128,
}

impl MatcherCall {
    pub fn parse(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < MATCHER_CALL_LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        if data[0] != MATCHER_CALL_TAG {
            return Err(ProgramError::InvalidInstructionData);
        }

        let req_id = u64::from_le_bytes(data[1..9].try_into().unwrap());
        let asset_index = u16::from_le_bytes(data[9..11].try_into().unwrap());
        let lp_account_id = u64::from_le_bytes(data[11..19].try_into().unwrap());
        let oracle_price_e6 = u64::from_le_bytes(data[19..27].try_into().unwrap());
        let req_size = i128::from_le_bytes(data[27..43].try_into().unwrap());

        for &b in &data[43..67] {
            if b != 0 {
                return Err(ProgramError::InvalidInstructionData);
            }
        }

        Ok(Self {
            req_id,
            asset_index,
            lp_account_id,
            oracle_price_e6,
            req_size,
        })
    }
}

// =============================================================================
// Instruction Processing
// =============================================================================

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    match instruction_data[0] {
        MATCHER_CALL_TAG => process_matcher_call(program_id, accounts, instruction_data),
        MATCHER_BATCH_CALL_TAG => process_batch_matcher_call(program_id, accounts, instruction_data),
        MATCHER_INIT_VAMM_TAG => vamm::process_init(program_id, accounts, instruction_data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Process Batched Matcher Call instruction (Tag 3)
///
/// Same accounts and signer/owner discipline as the single-fill call: the LP PDA must sign once
/// for the whole batch, and the context must be initialized and owned by this program.
fn process_batch_matcher_call(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let lp_pda = next_account_info(account_iter)?;
    let ctx_account = next_account_info(account_iter)?;

    if ctx_account.owner != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }
    if ctx_account.data_len() < MATCHER_CONTEXT_LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }
    // Mirror the writable + signer discipline from process_matcher_call.
    if !ctx_account.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    // Signer check before any account-data inspection (PM-3 pattern).
    if !lp_pda.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let is_initialized = {
        let ctx_data = ctx_account.try_borrow_data()?;
        vamm::MatcherCtx::is_initialized(&ctx_data[CTX_VAMM_OFFSET..])
    };
    if !is_initialized {
        return Err(ProgramError::UninitializedAccount);
    }
    vamm::process_batch_call(lp_pda, ctx_account, instruction_data)
}

fn process_matcher_call(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let lp_pda = next_account_info(account_iter)?;
    let ctx_account = next_account_info(account_iter)?;

    if ctx_account.owner != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }
    if ctx_account.data_len() < MATCHER_CONTEXT_LEN {
        return Err(ProgramError::AccountDataTooSmall);
    }
    // PM-1: mirror the writable check in `process_init`. Without this guard the
    // mutable borrow below (try_borrow_mut_data for return + ctx writes) would
    // surface only as an opaque runtime error; an explicit check at the
    // validation boundary keeps the failure mode auditable and prevents future
    // refactors from silently dropping the guard.
    if !ctx_account.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    // PM-3: signer check before any account-data inspection. Without this an
    // unauthenticated caller could distinguish initialized from uninitialized
    // ctx accounts via error-code observation.
    if !lp_pda.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let is_initialized = {
        let ctx_data = ctx_account.try_borrow_data()?;
        vamm::MatcherCtx::is_initialized(&ctx_data[CTX_VAMM_OFFSET..])
    };

    if !is_initialized {
        return Err(ProgramError::UninitializedAccount);
    }

    vamm::process_call(lp_pda, ctx_account, instruction_data)
}

#[cfg(not(feature = "no-entrypoint"))]
mod entrypoint {
    use crate::process_instruction as processor;
    #[allow(unused_imports)]
    use alloc::format;
    use solana_program::{
        account_info::AccountInfo, entrypoint, entrypoint::ProgramResult, pubkey::Pubkey,
    };

    entrypoint!(process_instruction);

    fn process_instruction(
        program_id: &Pubkey,
        accounts: &[AccountInfo],
        instruction_data: &[u8],
    ) -> ProgramResult {
        processor(program_id, accounts, instruction_data)
    }
}
