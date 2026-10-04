//! Shared LiteSVM harness for the matcher BPF program.
//!
//! Everything here drives the COMPILED program (`target/deploy/percolator_match.so`, and the
//! v1 baseline built from 12bd671) through real transactions. The host-side
//! `percolator_match` crate is used only for wire encoders and layout constants, never to
//! compute an expected result that the program is then compared against — expected values
//! are written out from the formulas in the test bodies.
#![allow(dead_code, clippy::result_large_err)]

use litesvm::types::{FailedTransactionMetadata, TransactionMetadata};
use litesvm::LiteSVM;
use percolator_match::v2::{CallExt, V2Config};
use percolator_match::vamm::{self, InitParams, MatcherCtx, OwnerProof, SetParams};
use percolator_match::{MatcherReturn, CTX_VAMM_OFFSET, MATCHER_CONTEXT_LEN};
use solana_account::Account;
use solana_instruction::{error::InstructionError, AccountMeta, Instruction};
use solana_keypair::{keypair_from_seed, Keypair};
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;
use std::path::PathBuf;

/// Same program id for v1 and v2 so that parity runs (two separate LiteSVM instances)
/// produce byte-identical transactions and contexts.
pub const PROGRAM_ID: Pubkey = Pubkey::new_from_array([0x4d; 32]);
pub const LP_ACCOUNT_ID: u64 = 0x1122_3344_5566_7788;
pub const SCRATCH_V1_SO: &str = "/private/tmp/claude-501/-Users-khubair/ca1cb77b-7cfc-4a17-9553-aef353ce4cb8/scratchpad/v1-12bd671/target/deploy/percolator_match.so";

pub type TxResult = Result<TransactionMetadata, FailedTransactionMetadata>;

/// v2 program under test (this branch). FAILS (never skips) if it has not been built.
pub fn v2_so_path() -> PathBuf {
    let p = std::env::var("V2_SO").map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/deploy/percolator_match.so")
    });
    assert!(
        p.exists(),
        "v2 program .so not found at {} — run `cargo build-sbf` in the repo root first \
         (or set V2_SO). These tests must not pass without the compiled program.",
        p.display()
    );
    p
}

/// v1 baseline (12bd671, the deployed matcher). FAILS if absent.
pub fn v1_so_path() -> PathBuf {
    let p = PathBuf::from(std::env::var("V1_SO").unwrap_or_else(|_| SCRATCH_V1_SO.to_string()));
    assert!(
        p.exists(),
        "v1 baseline .so not found at {} — build 12bd671 with `git archive 12bd671 | tar -x -C \
         <dir> && cargo build-sbf` there and set V1_SO. The parity test must not pass without it.",
        p.display()
    );
    p
}

pub fn seeded_keypair(tag: u8) -> Keypair {
    let mut seed = [0u8; 32];
    seed[0] = tag;
    seed[31] = 0xa5;
    keypair_from_seed(&seed).unwrap()
}

pub struct Env {
    pub svm: LiteSVM,
    pub payer: Keypair,
}

impl Env {
    pub fn new(so: &std::path::Path) -> Self {
        let bytes = std::fs::read(so).unwrap();
        let mut svm = LiteSVM::new().with_transaction_history(0);
        svm.add_program(PROGRAM_ID, &bytes);
        let payer = seeded_keypair(200);
        svm.airdrop(&payer.pubkey(), 1_000_000_000_000).unwrap();
        Env { svm, payer }
    }
    pub fn v2() -> Self {
        Self::new(&v2_so_path())
    }
    pub fn v1() -> Self {
        Self::new(&v1_so_path())
    }

    /// Allocate a zeroed 320-byte context owned by the program.
    pub fn alloc_ctx(&mut self, key: Pubkey) {
        self.svm
            .set_account(
                key,
                Account {
                    lamports: 10_000_000,
                    data: vec![0; MATCHER_CONTEXT_LEN],
                    owner: PROGRAM_ID,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
    }

    pub fn ctx_data(&self, key: &Pubkey) -> Vec<u8> {
        self.svm.get_account(key).unwrap().data
    }

    pub fn ctx_struct(&self, key: &Pubkey) -> MatcherCtx {
        MatcherCtx::read_from(&self.ctx_data(key)[CTX_VAMM_OFFSET..]).unwrap()
    }

    /// Send one instruction. `authority` is account 0; it signs iff `sign` is true. The
    /// fee payer is always a separate funded keypair, so "unsigned authority" is a real
    /// transaction the runtime accepts and the program sees `is_signer == false`.
    pub fn send(&mut self, authority: &Keypair, sign: bool, ctx: &Pubkey, data: Vec<u8>) -> TxResult {
        self.send_as(authority.pubkey(), if sign { Some(authority) } else { None }, ctx, data)
    }

    pub fn send_as(
        &mut self,
        authority: Pubkey,
        signer: Option<&Keypair>,
        ctx: &Pubkey,
        data: Vec<u8>,
    ) -> TxResult {
        let ix = Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new_readonly(authority, signer.is_some()),
                AccountMeta::new(*ctx, false),
            ],
            data,
        };
        let msg = Message::new(&[ix], Some(&self.payer.pubkey()));
        let bh = self.svm.latest_blockhash();
        let tx = match signer {
            Some(s) => Transaction::new(&[&self.payer, s], msg, bh),
            None => Transaction::new(&[&self.payer], msg, bh),
        };
        let r = self.svm.send_transaction(tx);
        self.svm.expire_blockhash();
        r
    }

    pub fn warp(&mut self, slot: u64) {
        self.svm.warp_to_slot(slot);
    }

    // ---- program ops ---------------------------------------------------------

    pub fn init(&mut self, lp: &Keypair, ctx: &Pubkey, p: &InitParams) -> TxResult {
        self.send(lp, true, ctx, p.encode().to_vec())
    }

    /// Allocate + init; panics on failure.
    pub fn new_ctx(&mut self, lp: &Keypair, p: &InitParams) -> Pubkey {
        let key = Pubkey::new_unique();
        self.alloc_ctx(key);
        self.init(lp, &key, p).expect("init");
        key
    }

    /// Tag 0 call. Returns the MatcherReturn read from ctx bytes 0..64 on success.
    pub fn call(
        &mut self,
        lp: &Keypair,
        ctx: &Pubkey,
        c: &Call,
    ) -> Result<(MatcherReturn, TransactionMetadata), FailedTransactionMetadata> {
        let meta = self.send(lp, true, ctx, c.encode())?;
        let ret = decode_return(&self.ctx_data(ctx)[..64]);
        Ok((ret, meta))
    }

    pub fn call_raw(&mut self, lp: &Keypair, ctx: &Pubkey, data: Vec<u8>) -> TxResult {
        self.send(lp, true, ctx, data)
    }

    /// Tag 3 batch. Returns the per-leg MatcherReturns from transaction return data.
    pub fn batch(
        &mut self,
        lp: &Keypair,
        ctx: &Pubkey,
        b: &Batch,
    ) -> Result<(Vec<MatcherReturn>, TransactionMetadata), FailedTransactionMetadata> {
        let meta = self.send(lp, true, ctx, b.encode())?;
        assert_eq!(meta.return_data.program_id, PROGRAM_ID);
        let rd = &meta.return_data.data;
        assert_eq!(rd.len(), 64 * b.legs.len(), "batch return data length");
        let rets = rd.chunks(64).map(decode_return).collect();
        Ok((rets, meta))
    }

    pub fn configure_lp_pda(&mut self, lp: &Keypair, ctx: &Pubkey, op_payload: &[u8]) -> TxResult {
        self.send(lp, true, ctx, vamm::encode_configure(None, op_payload))
    }

    pub fn set_params(&mut self, lp: &Keypair, ctx: &Pubkey, p: &SetParams) -> TxResult {
        self.configure_lp_pda(lp, ctx, &op_set_params(p))
    }
}

pub fn op_set_params(p: &SetParams) -> Vec<u8> {
    let mut v = vec![vamm::CONFIGURE_OP_SET_PARAMS];
    v.extend_from_slice(&p.encode());
    v
}

pub fn op_cap(cap: u16) -> Vec<u8> {
    let mut v = vec![vamm::CONFIGURE_OP_BACKING_FEE_CAP];
    v.extend_from_slice(&cap.to_le_bytes());
    v
}

pub fn owner_proof_ix(proof: &OwnerProof, op_payload: &[u8]) -> Vec<u8> {
    vamm::encode_configure(Some(proof), op_payload)
}

pub fn decode_return(b: &[u8]) -> MatcherReturn {
    MatcherReturn {
        abi_version: u32::from_le_bytes(b[0..4].try_into().unwrap()),
        flags: u32::from_le_bytes(b[4..8].try_into().unwrap()),
        exec_price_e6: u64::from_le_bytes(b[8..16].try_into().unwrap()),
        exec_size: i128::from_le_bytes(b[16..32].try_into().unwrap()),
        req_id: u64::from_le_bytes(b[32..40].try_into().unwrap()),
        lp_account_id: u64::from_le_bytes(b[40..48].try_into().unwrap()),
        oracle_price_e6: u64::from_le_bytes(b[48..56].try_into().unwrap()),
        asset_index: u64::from_le_bytes(b[56..64].try_into().unwrap()),
    }
}

/// The InstructionError of a failed single-instruction transaction.
pub fn ix_err(r: &FailedTransactionMetadata) -> InstructionError {
    match &r.err {
        TransactionError::InstructionError(0, e) => e.clone(),
        other => panic!("expected an InstructionError on ix 0, got {other:?}"),
    }
}

pub fn expect_err<T: std::fmt::Debug>(r: Result<T, FailedTransactionMetadata>) -> InstructionError {
    match r {
        Ok(v) => panic!("expected the transaction to FAIL, it succeeded: {v:?}"),
        Err(e) => ix_err(&e),
    }
}

pub fn custom(code: u32) -> InstructionError {
    InstructionError::Custom(code)
}

// ---- call builders -----------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct Call {
    pub req_id: u64,
    pub asset: u16,
    pub lp_id: u64,
    pub oracle: u64,
    pub size: i128,
    pub ext: [u8; 24],
}

impl Call {
    pub fn new(req_id: u64, oracle: u64, size: i128) -> Self {
        Call {
            req_id,
            asset: 0,
            lp_id: LP_ACCOUNT_ID,
            oracle,
            size,
            ext: [0; 24],
        }
    }
    pub fn asset(mut self, a: u16) -> Self {
        self.asset = a;
        self
    }
    pub fn ext(mut self, e: CallExt) -> Self {
        self.ext = e.encode();
        self
    }
    pub fn ext_raw(mut self, e: [u8; 24]) -> Self {
        self.ext = e;
        self
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut d = vec![0u8; 67];
        d[0] = 0;
        d[1..9].copy_from_slice(&self.req_id.to_le_bytes());
        d[9..11].copy_from_slice(&self.asset.to_le_bytes());
        d[11..19].copy_from_slice(&self.lp_id.to_le_bytes());
        d[19..27].copy_from_slice(&self.oracle.to_le_bytes());
        d[27..43].copy_from_slice(&self.size.to_le_bytes());
        d[43..67].copy_from_slice(&self.ext);
        d
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Leg {
    pub asset: u16,
    pub oracle: u64,
    pub size: i128,
    pub ext: [u8; 24],
}

impl Leg {
    pub fn new(asset: u16, oracle: u64, size: i128) -> Self {
        Leg {
            asset,
            oracle,
            size,
            ext: [0; 24],
        }
    }
    pub fn ext(mut self, e: CallExt) -> Self {
        self.ext = e.encode();
        self
    }
}

#[derive(Clone, Debug)]
pub struct Batch {
    pub req_id: u64,
    pub lp_id: u64,
    pub legs: Vec<Leg>,
    /// true = append the per-leg 24-byte extension trailer (v2 length); false = legacy.
    pub with_ext: bool,
}

impl Batch {
    pub fn legacy(req_id: u64, legs: Vec<Leg>) -> Self {
        Batch {
            req_id,
            lp_id: LP_ACCOUNT_ID,
            legs,
            with_ext: false,
        }
    }
    pub fn with_ext(req_id: u64, legs: Vec<Leg>) -> Self {
        Batch {
            req_id,
            lp_id: LP_ACCOUNT_ID,
            legs,
            with_ext: true,
        }
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut d = vec![3u8, self.legs.len() as u8];
        d.extend_from_slice(&self.req_id.to_le_bytes());
        d.extend_from_slice(&self.lp_id.to_le_bytes());
        for l in &self.legs {
            d.extend_from_slice(&l.asset.to_le_bytes());
            d.extend_from_slice(&l.oracle.to_le_bytes());
            d.extend_from_slice(&l.size.to_le_bytes());
        }
        if self.with_ext {
            for l in &self.legs {
                d.extend_from_slice(&l.ext);
            }
        }
        d
    }
}

// ---- parameter builders ------------------------------------------------------

pub fn init_params(kind: u8) -> InitParams {
    InitParams {
        kind,
        trading_fee_bps: 10,
        base_spread_bps: 20,
        max_total_bps: 500,
        impact_k_bps: if kind == 1 { 1000 } else { 0 },
        liquidity_notional_e6: if kind == 1 { 10_000_000_000_000 } else { 0 },
        max_fill_abs: u128::MAX,
        max_inventory_abs: 0,
        fee_to_insurance_bps: 0,
        skew_spread_mult_bps: 0,
        lp_account_id: LP_ACCOUNT_ID,
    }
}

/// SetParams that copies the core fields of `ip` and attaches the given v2 config.
pub fn set_params_from(ip: &InitParams, enable_v2: bool, v2: V2Config) -> SetParams {
    SetParams {
        kind: ip.kind,
        trading_fee_bps: ip.trading_fee_bps,
        base_spread_bps: ip.base_spread_bps,
        max_total_bps: ip.max_total_bps,
        impact_k_bps: ip.impact_k_bps,
        liquidity_notional_e6: ip.liquidity_notional_e6,
        max_fill_abs: ip.max_fill_abs,
        max_inventory_abs: ip.max_inventory_abs,
        fee_to_insurance_bps: ip.fee_to_insurance_bps,
        skew_spread_mult_bps: ip.skew_spread_mult_bps,
        enable_v2,
        v2,
    }
}

/// A kind-2 v2 config with a FIXED fee (lo == hi == cold == fee, vol terms off, warm), no
/// skew, no staleness guards. Individual tests switch on exactly the mechanism under test.
pub fn fixed_fee_v2(fee: u16) -> V2Config {
    V2Config {
        flags: 0,
        fee_lo_bps: fee,
        fee_hi_bps: fee,
        fee_cold_bps: fee,
        vol_a_milli: 0,
        vol_b_den: 0,
        vol_alpha_bps: 10_000,
        vol_warmup: 0,
        vol_move_cap_10bps: 100,
        vol_ref_slots: 1,
        thin_rebate_mult_bps: 0,
        skew_cap_bps: 0,
        rebate_cap_bps: 0,
        max_mark_age_slots: 0,
        observed_stale_slots: 0,
        skew_ref_inventory: 0,
    }
}

/// Price math the tests assert against (written out, not imported from the crate).
pub fn ask(oracle: u64, total_bps: u128) -> u64 {
    let n = oracle as u128 * (10_000 + total_bps);
    n.div_ceil(10_000) as u64
}
pub fn bid(oracle: u64, total_bps: u128) -> u64 {
    (oracle as u128 * (10_000 - total_bps) / 10_000) as u64
}

/// Exact taker spread in bps paid on a fill, as a rational (num, den) for comparisons.
pub fn spread_ppm(oracle: u64, exec: u64) -> i128 {
    (exec as i128 - oracle as i128) * 1_000_000 / oracle as i128
}

pub fn ctx_v2_raw(data: &[u8]) -> &[u8] {
    &data[CTX_VAMM_OFFSET + 178..CTX_VAMM_OFFSET + 256]
}
