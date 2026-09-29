//! INDEPENDENT SUITE (2026-09-30) — P2 matcher v2, LiteSVM against the compiled .so.
//!
//! Written from the DESIGN DOCS only:
//!   * ledger/p2-matcher-v2-2026-09-29.md  FE.1 (ctx layout), FE.2 (reference quote), FE.3
//!   * docs/MATCHER_V2_ABI.md / ledger/p1-p2-matcher-call-extension-abi-2026-09-30.md
//!     §1-2 (call extension), §5 (tag 5), §6 (errors), §7 (kind-2 pricing), §9 (SetParams)
//! The reference quote below is an independent Rust port of the doc's TypeScript FE.2.
//!
//! .so under test: INDEP_MATCHER_SO (default ~/wt-indep/so/matcher-p2.so).
//! Negative control: INDEP_MATCHER_SO=~/wt-indep/baseline-so/matcher-12bd671.so — the v2
//! feature tests must fail there; the `inv_*` invariant tests (kinds 0/1) must pass on both.
#![allow(clippy::too_many_arguments)]

use litesvm::LiteSVM;
use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;
use solana_sdk::{
    account::Account,
    instruction::{AccountMeta, Instruction, InstructionError},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::{Transaction, TransactionError},
};

const CTX_LEN: usize = 320;
const BPS: u128 = 10_000;
const LP_ID: u64 = 7;

// ext flags (§2)
const X_HEADROOM: u8 = 1;
const X_MARK_SLOT: u8 = 2;
const X_TAKER_REDUCING: u8 = 8;
const X_EXEC_BAND: u8 = 16;

fn scale() -> usize {
    std::env::var("INDEP_SCALE").ok().and_then(|v| v.parse().ok()).unwrap_or(1)
}

fn so_path() -> String {
    std::env::var("INDEP_MATCHER_SO").unwrap_or_else(|_| {
        format!("{}/wt-indep/so/matcher-p2.so", std::env::var("HOME").unwrap())
    })
}

#[derive(Clone, Copy, Debug, Default)]
struct Ret {
    flags: u32,
    price: u64,
    size: i128,
}

#[derive(Clone, Copy, Debug)]
struct Core {
    kind: u8,
    trading_fee: u32,
    base: u32,
    max_total: u32,
    impact_k: u32,
    liq: u128,
    max_fill: u128,
    max_inv: u128,
    skew_mult: u16,
}

#[derive(Clone, Copy, Debug, Default)]
struct V2 {
    flags: u8,
    fee_lo: u16,
    fee_hi: u16,
    fee_cold: u16,
    vol_a: u16,
    vol_b_den: u16,
    vol_alpha: u16,
    warmup: u8,
    move_cap: u8,
    vol_ref: u16,
    thin_rebate: u16,
    skew_cap: u16,
    rebate_cap: u16,
    max_mark_age: u16,
    observed_stale: u16,
    skew_ref: u64,
}

struct Env {
    svm: LiteSVM,
    prog: Pubkey,
    lp: Keypair,
    ctx: Pubkey,
    payer: Keypair,
    req: u64,
}

fn custom(e: &TransactionError) -> Option<u32> {
    match e {
        TransactionError::InstructionError(_, InstructionError::Custom(c)) => Some(*c),
        _ => None,
    }
}

impl Env {
    fn new() -> Self {
        let mut svm = LiteSVM::new();
        let prog = Pubkey::new_unique();
        svm.add_program_from_file(prog, so_path()).expect("matcher .so");
        let payer = Keypair::new();
        let lp = Keypair::new();
        svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();
        svm.airdrop(&lp.pubkey(), 1_000_000_000).unwrap();
        let ctx = Pubkey::new_unique();
        svm.set_account(
            ctx,
            Account { lamports: 10_000_000, data: vec![0; CTX_LEN], owner: prog, executable: false, rent_epoch: 0 },
        )
        .unwrap();
        svm.warp_to_slot(100);
        Env { svm, prog, lp, ctx, payer, req: 1 }
    }

    fn send(&mut self, data: Vec<u8>) -> Result<(), TransactionError> {
        self.svm.expire_blockhash();
        let ix = Instruction {
            program_id: self.prog,
            accounts: vec![AccountMeta::new_readonly(self.lp.pubkey(), true), AccountMeta::new(self.ctx, false)],
            data,
        };
        let tx = Transaction::new_signed_with_payer(&[ix], Some(&self.payer.pubkey()), &[&self.payer, &self.lp], self.svm.latest_blockhash());
        self.svm.send_transaction(tx).map(|_| ()).map_err(|e| e.err)
    }

    /// Tag 2 init (78 B; FE/§ wrapper tag-83 payload shape).
    fn init(&mut self, c: Core) -> Result<(), TransactionError> {
        let mut d = vec![0u8; 78];
        d[0] = 2;
        d[1] = c.kind;
        d[2..6].copy_from_slice(&c.trading_fee.to_le_bytes());
        d[6..10].copy_from_slice(&c.base.to_le_bytes());
        d[10..14].copy_from_slice(&c.max_total.to_le_bytes());
        d[14..18].copy_from_slice(&c.impact_k.to_le_bytes());
        d[18..34].copy_from_slice(&c.liq.to_le_bytes());
        d[34..50].copy_from_slice(&c.max_fill.to_le_bytes());
        d[50..66].copy_from_slice(&c.max_inv.to_le_bytes());
        d[68..70].copy_from_slice(&c.skew_mult.to_le_bytes());
        d[70..78].copy_from_slice(&LP_ID.to_le_bytes());
        self.send(d)
    }

    /// Tag 5, auth 0 (lp_pda signature), op 1 SetParams (§9, 105 bytes).
    fn set_params(&mut self, c: Core, v: Option<V2>) -> Result<(), TransactionError> {
        let mut p = vec![0u8; 105];
        p[0] = c.kind;
        p[1..5].copy_from_slice(&c.trading_fee.to_le_bytes());
        p[5..9].copy_from_slice(&c.base.to_le_bytes());
        p[9..13].copy_from_slice(&c.max_total.to_le_bytes());
        p[13..17].copy_from_slice(&c.impact_k.to_le_bytes());
        p[17..33].copy_from_slice(&c.liq.to_le_bytes());
        p[33..49].copy_from_slice(&c.max_fill.to_le_bytes());
        p[49..65].copy_from_slice(&c.max_inv.to_le_bytes());
        p[67..69].copy_from_slice(&c.skew_mult.to_le_bytes());
        if let Some(v) = v {
            p[69] = 1;
            p[70] = v.flags;
            let w16 = |p: &mut Vec<u8>, o: usize, x: u16| p[o..o + 2].copy_from_slice(&x.to_le_bytes());
            w16(&mut p, 71, v.fee_lo);
            w16(&mut p, 73, v.fee_hi);
            w16(&mut p, 75, v.fee_cold);
            w16(&mut p, 77, v.vol_a);
            w16(&mut p, 79, v.vol_b_den);
            w16(&mut p, 81, v.vol_alpha);
            p[83] = v.warmup;
            p[84] = v.move_cap;
            w16(&mut p, 85, v.vol_ref);
            w16(&mut p, 87, v.thin_rebate);
            w16(&mut p, 89, v.skew_cap);
            w16(&mut p, 91, v.rebate_cap);
            w16(&mut p, 93, v.max_mark_age);
            w16(&mut p, 95, v.observed_stale);
            p[97..105].copy_from_slice(&v.skew_ref.to_le_bytes());
        }
        let mut d = vec![5u8, 0u8, 1u8];
        d.extend_from_slice(&p);
        self.send(d)
    }

    fn call_raw(&mut self, oracle: u64, size: i128, tail: [u8; 24]) -> Result<Ret, TransactionError> {
        let mut d = vec![0u8; 67];
        d[0] = 0;
        d[1..9].copy_from_slice(&self.req.to_le_bytes());
        self.req += 1;
        d[9..11].copy_from_slice(&0u16.to_le_bytes());
        d[11..19].copy_from_slice(&LP_ID.to_le_bytes());
        d[19..27].copy_from_slice(&oracle.to_le_bytes());
        d[27..43].copy_from_slice(&size.to_le_bytes());
        d[43..67].copy_from_slice(&tail);
        self.send(d)?;
        let a = self.svm.get_account(&self.ctx).unwrap().data;
        Ok(Ret {
            flags: u32::from_le_bytes(a[4..8].try_into().unwrap()),
            price: u64::from_le_bytes(a[8..16].try_into().unwrap()),
            size: i128::from_le_bytes(a[16..32].try_into().unwrap()),
        })
    }

    fn call(&mut self, oracle: u64, size: i128) -> Result<Ret, TransactionError> {
        self.call_raw(oracle, size, [0; 24])
    }

    fn call_ext(&mut self, oracle: u64, size: i128, flags: u8, band: u16, mark_slot: u64, headroom: u64) -> Result<Ret, TransactionError> {
        let mut t = [0u8; 24];
        t[0] = 1;
        t[1] = flags;
        t[2..4].copy_from_slice(&band.to_le_bytes());
        t[4..12].copy_from_slice(&mark_slot.to_le_bytes());
        t[12..20].copy_from_slice(&headroom.to_le_bytes());
        self.call_raw(oracle, size, t)
    }

    fn ctx_bytes(&self) -> Vec<u8> {
        self.svm.get_account(&self.ctx).unwrap().data
    }
    fn restore(&mut self, data: Vec<u8>) {
        let mut a = self.svm.get_account(&self.ctx).unwrap();
        a.data = data;
        self.svm.set_account(self.ctx, a).unwrap();
    }
    fn inventory(&self) -> i128 {
        i128::from_le_bytes(self.ctx_bytes()[160..176].try_into().unwrap())
    }
    fn slot(&self) -> u64 {
        self.svm.get_sysvar::<solana_sdk::clock::Clock>().slot
    }
}

// ─────────────────────────── independent reference model (doc FE.2) ───────────────────────────

#[derive(Clone, Copy, Debug)]
struct St {
    var_e4: u128,
    warm_left: u8,
    last_price: u64,
    last_slot: u64,
    inv: i128,
}

fn read_state(e: &Env) -> St {
    let a = e.ctx_bytes();
    St {
        var_e4: u64::from_le_bytes(a[280..288].try_into().unwrap()) as u128,
        warm_left: a[256],
        last_price: u64::from_le_bytes(a[288..296].try_into().unwrap()),
        last_slot: u64::from_le_bytes(a[296..304].try_into().unwrap()),
        inv: i128::from_le_bytes(a[160..176].try_into().unwrap()),
    }
}

fn ceil_div(a: u128, b: u128) -> u128 {
    a / b + if a % b != 0 { 1 } else { 0 }
}
fn isqrt(n: u128) -> u128 {
    if n < 2 {
        return n;
    }
    let (mut x, mut y) = (n, (n + 1) / 2);
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

fn vol_update(v: &V2, s: &mut St, price: u64, now: u64) {
    if price == 0 {
        return;
    }
    if s.last_price == 0 {
        s.last_price = price;
        s.last_slot = now;
        return;
    }
    if now < s.last_slot {
        return;
    }
    let dt = (now - s.last_slot) as u128;
    let rf = (v.vol_ref as u128).max(1);
    if dt < rf {
        return;
    }
    let last = s.last_price as u128;
    let cap = (v.move_cap as u128).max(1) * 10;
    let mv = ((price as i128 - last as i128).unsigned_abs() * BPS / last).min(cap);
    let r2 = (mv * mv * 10_000 * rf / dt).min(cap * cap * 10_000);
    let alpha = (v.vol_alpha as i128).clamp(1, 10_000);
    let delta = (r2 as i128 - s.var_e4 as i128) * alpha / 10_000;
    s.var_e4 = ((s.var_e4 as i128 + delta).max(0) as u128).min(u64::MAX as u128);
    s.warm_left = s.warm_left.saturating_sub(1);
    s.last_price = price;
    s.last_slot = now;
}

fn adaptive_fee(v: &V2, s: &St) -> u128 {
    let lo = v.fee_lo as u128;
    let hi = (v.fee_hi as u128).max(lo);
    if s.warm_left > 0 {
        return (v.fee_cold as u128).max(lo).min(hi);
    }
    let sig = isqrt(s.var_e4);
    let lin = v.vol_a as u128 * sig / 100_000;
    let quad = if v.vol_b_den == 0 { 0 } else { s.var_e4 / (v.vol_b_den as u128 * 10_000) };
    (lo + lin + quad).max(lo).min(hi)
}

fn skew_pot(x: u128, mult: u128, cap: u128, rf: u128) -> u128 {
    if mult == 0 || cap == 0 || x == 0 {
        return 0;
    }
    let knee = cap * rf / mult;
    if x <= knee {
        mult * x * x
    } else {
        mult * knee * knee + 2 * rf * cap * (x - knee)
    }
}

fn skew_net(inv: i128, fill: u128, lp_sells: bool, s: u128, r: u128, sc: u128, rc: u128, rf: u128) -> i128 {
    if fill == 0 || rf == 0 || (s == 0 && r == 0) {
        return 0;
    }
    let post = if lp_sells { inv - fill as i128 } else { inv + fill as i128 };
    let (a, b) = (inv.unsigned_abs(), post.unsigned_abs());
    let crosses = (inv > 0 && post < 0) || (inv < 0 && post > 0);
    let (pos, neg) = if crosses {
        (skew_pot(b, s, sc, rf), skew_pot(a, r, rc, rf))
    } else if b >= a {
        (skew_pot(b, s, sc, rf) - skew_pot(a, s, sc, rf), 0)
    } else {
        (0, skew_pot(a, r, rc, rf) - skew_pot(b, r, rc, rf))
    };
    let den = 2 * rf * fill;
    if pos >= neg {
        ceil_div(pos - neg, den) as i128
    } else {
        -(((neg - pos) / den) as i128)
    }
}

fn inv_clip(inv: i128, max_inv: u128, fill: u128, buys: bool) -> u128 {
    if max_inv == 0 {
        return fill;
    }
    let m = max_inv as i128;
    let new = if buys { inv - fill as i128 } else { inv + fill as i128 };
    if new.unsigned_abs() <= max_inv {
        return fill;
    }
    if buys {
        if inv <= -m {
            return 0;
        }
        fill.min((inv + m).unsigned_abs())
    } else {
        if inv >= m {
            return 0;
        }
        fill.min((m - inv).unsigned_abs())
    }
}

/// (fill, price) per FE.2 quoteKind2.
fn model_kind2(c: &Core, v: &V2, st: St, oracle: u64, req: i128, now: u64, band: Option<u128>, headroom: Option<u128>) -> Option<(u128, u64)> {
    let mut s = st;
    vol_update(v, &mut s, oracle, now);
    let fee = adaptive_fee(v, &s);
    let buys = req > 0;
    let mut max_fill = c.max_fill.min(i128::MAX as u128);
    if let Some(h) = headroom {
        max_fill = max_fill.min(h);
    }
    let mut max_total = c.max_total as u128;
    if let Some(b) = band {
        max_total = max_total.min(b);
    }
    max_total = max_total.min(9000);
    let mut fill = if max_fill == 0 { 0 } else { req.unsigned_abs().min(max_fill) };
    fill = inv_clip(st.inv, c.max_inv, fill, buys);
    let req_fill = fill;
    if fill == 0 {
        return Some((0, oracle));
    }
    let (s_m, r_m, sc, rc, rf) = (c.skew_mult as u128, v.thin_rebate as u128, v.skew_cap as u128, v.rebate_cap as u128, v.skew_ref as u128);
    let (base, k, d) = (c.base as u128, c.impact_k as u128, c.liq);
    let impact_skew = |f: u128| -> Option<(u128, i128)> {
        let n = f.checked_mul(oracle as u128)? / 1_000_000;
        let imp = if k == 0 || n == 0 {
            0
        } else if n >= d {
            u128::MAX
        } else {
            ceil_div(k * n, d - n)
        };
        Some((imp, skew_net(st.inv, f, buys, s_m, r_m, sc, rc, rf)))
    };
    let gross = |f: u128| -> Option<u128> {
        if f == 0 {
            return Some(0);
        }
        let (i, sk) = impact_skew(f)?;
        Some(base.saturating_add(fee).saturating_add(i).saturating_add(sk.max(0) as u128))
    };
    if gross(fill)? > max_total {
        let (mut lo, mut hi, mut it) = (0u128, fill, 0);
        while hi - lo > 1 && it < 128 {
            let mid = lo + (hi - lo) / 2;
            if gross(mid)? <= max_total {
                lo = mid
            } else {
                hi = mid
            }
            it += 1;
        }
        fill = lo;
    }
    let lp_reduces = (buys && st.inv > 0) || (!buys && st.inv < 0);
    if lp_reduces {
        fill = fill.max(req_fill.min(st.inv.unsigned_abs()));
    }
    if fill == 0 {
        return Some((0, oracle));
    }
    let (imp, sk) = impact_skew(fill)?;
    let imp = imp.min(9000);
    let total = ((base + fee + imp) as i128 + sk).max(0) as u128;
    let total = total.min(max_total);
    let o = oracle as u128;
    let price = if buys { ceil_div(o * (BPS + total), BPS) } else { o * (BPS - total) / BPS };
    Some((fill, price as u64))
}

fn default_v2() -> V2 {
    V2 {
        flags: 1, // STALE_ALLOW_REDUCING
        fee_lo: 10,
        fee_hi: 80,
        fee_cold: 10,
        vol_a: 1000,
        vol_b_den: 100,
        vol_alpha: 1000,
        warmup: 8,
        move_cap: 100,
        vol_ref: 25,
        thin_rebate: 150,
        skew_cap: 100,
        rebate_cap: 50,
        max_mark_age: 150,
        observed_stale: 0,
        skew_ref: 1_000_000_000,
    }
}

fn tuned_core() -> Core {
    // doc §6 "Recommended launch config", LP capital $10k
    Core {
        kind: 2,
        trading_fee: 10,
        base: 20,
        max_total: 100,
        impact_k: 5000,
        liq: 100_000_000_000,
        max_fill: 1_000_000_000,
        max_inv: 4_000_000_000,
        skew_mult: 300,
    }
}

fn kind2_env(c: Core, v: V2) -> Env {
    let mut e = Env::new();
    e.init(Core { kind: 0, ..c }).expect("tag 2 init (kind 0)");
    e.set_params(c, Some(v)).unwrap_or_else(|err| panic!("tag 5 op 1 SetParams kind 2 must succeed on v2: {err:?}"));
    e
}

fn rand_v2(rng: &mut XorShiftRng) -> V2 {
    let fee_lo = rng.gen_range(0..40u16);
    let fee_hi = fee_lo + rng.gen_range(0..100u16);
    let skew_cap = rng.gen_range(0..200u16);
    V2 {
        flags: 1,
        fee_lo,
        fee_hi,
        fee_cold: rng.gen_range(fee_lo..=fee_hi),
        vol_a: rng.gen_range(0..3000),
        vol_b_den: rng.gen_range(0..300),
        vol_alpha: rng.gen_range(1..=10_000),
        warmup: rng.gen_range(0..4),
        move_cap: rng.gen_range(1..=200),
        vol_ref: rng.gen_range(1..40),
        thin_rebate: 0,
        skew_cap,
        rebate_cap: rng.gen_range(0..=skew_cap),
        max_mark_age: 0,
        observed_stale: 0,
        skew_ref: rng.gen_range(1..2_000_000_000u64),
    }
}

fn rand_core(rng: &mut XorShiftRng) -> Core {
    let base = rng.gen_range(0..40u32);
    Core {
        kind: 2,
        trading_fee: 0,
        base,
        max_total: base + 140 + rng.gen_range(0..300u32),
        impact_k: rng.gen_range(0..20_000),
        liq: rng.gen_range(1_000_000..1_000_000_000_000u128),
        max_fill: rng.gen_range(1..10_000_000_000u128),
        max_inv: if rng.gen_bool(0.3) { 0 } else { rng.gen_range(1..20_000_000_000u128) },
        skew_mult: rng.gen_range(0..600),
    }
}

// ─────────────────────────── invariant tests (must pass on v1 AND v2) ───────────────────────────

/// README ABI: |exec_size| <= |req|, sign matches, price never on the wrong side of the
/// oracle for kinds 0/1 (legacy call). Passes on the deployed 12bd671 too.
#[test]
fn inv_kind01_price_never_crosses_oracle_and_size_bounded() {
    let mut rng = XorShiftRng::seed_from_u64(0xA11CE);
    let mut fills = 0;
    for _case in 0..60 * scale() {
        let mut e = Env::new();
        let kind = rng.gen_range(0..2u8);
        let c = Core {
            kind,
            trading_fee: rng.gen_range(0..50),
            base: rng.gen_range(0..50),
            max_total: rng.gen_range(100..900),
            impact_k: if kind == 1 { rng.gen_range(1..500) } else { 0 },
            liq: if kind == 1 { rng.gen_range(1_000_000..1_000_000_000_000) } else { 0 },
            max_fill: rng.gen_range(1..5_000_000_000),
            max_inv: rng.gen_range(0..10_000_000_000),
            skew_mult: rng.gen_range(0..300),
        };
        e.init(c).unwrap_or_else(|err| panic!("init {c:?}: {err:?}"));
        for _ in 0..15 {
            let oracle = rng.gen_range(1_000..10_000_000_000u64);
            let req = rng.gen_range(-3_000_000_000i128..3_000_000_000);
            if req == 0 {
                continue;
            }
            match e.call(oracle, req) {
                Ok(r) => {
                    assert!(r.size.unsigned_abs() <= req.unsigned_abs(), "fill > request");
                    if r.size != 0 {
                        fills += 1;
                        assert_eq!(r.size.signum(), req.signum(), "fill sign flipped");
                        if req > 0 {
                            assert!(r.price >= oracle, "buy below oracle: {} < {oracle}", r.price);
                        } else {
                            assert!(r.price <= oracle, "sell above oracle: {} > {oracle}", r.price);
                        }
                        let dev = (r.price as i128 - oracle as i128).unsigned_abs();
                        assert!(dev <= ceil_div(oracle as u128 * c.max_total as u128, BPS), "price outside max_total");
                    }
                }
                Err(_) => {}
            }
        }
    }
    assert!(fills > 100, "vacuous: only {fills} fills");
}

// ─────────────────────────── v2 feature tests (must FAIL on 12bd671) ───────────────────────────

/// Differential: the on-chain kind-2 quote equals an independent port of the doc's FE.2
/// reference (bit-exact), over random configs/states/requests/slots.
#[test]
fn p2_kind2_quote_matches_doc_reference_model_bit_exact() {
    let mut rng = XorShiftRng::seed_from_u64(0xFE2);
    let (mut n, mut filled) = (0, 0);
    let mut mism = Vec::new();
    for _case in 0..40 * scale() {
        let c = rand_core(&mut rng);
        let v = rand_v2(&mut rng);
        let mut e = kind2_env(c, v);
        let mut oracle: u64 = rng.gen_range(100_000..100_000_000);
        for _ in 0..25 {
            let s = e.slot() + rng.gen_range(0..60);
            e.svm.warp_to_slot(s);
            let step = rng.gen_range(-300i64..=300);
            oracle = ((oracle as i128) * (10_000 + step as i128) / 10_000).max(1_000) as u64;
            let req = rng.gen_range(-4_000_000_000i128..4_000_000_000);
            if req == 0 {
                continue;
            }
            let st = read_state(&e);
            let want = model_kind2(&c, &v, st, oracle, req, e.slot(), None, None);
            let got = e.call(oracle, req);
            n += 1;
            match (want, got) {
                (Some((wf, wp)), Ok(r)) => {
                    if r.size != 0 {
                        filled += 1;
                    }
                    let gp = if r.size == 0 { oracle } else { r.price };
                    if r.size.unsigned_abs() != wf || (wf != 0 && gp != wp) {
                        mism.push(format!("c={c:?} v={v:?} st={st:?} oracle={oracle} req={req} slot={}: model fill {wf} price {wp}; chain fill {} price {}", e.slot(), r.size, r.price));
                    }
                }
                (None, Err(_)) => {}
                (w, g) => mism.push(format!("c={c:?} st={st:?} oracle={oracle} req={req}: model {w:?} chain {g:?}")),
            }
        }
    }
    assert!(filled > 50, "vacuous: {filled}/{n} fills");
    assert!(mism.is_empty(), "{} of {n} quotes differ from the doc reference:\n{}", mism.len(), mism.iter().take(5).cloned().collect::<Vec<_>>().join("\n"));
}

/// Spec §7: price never crosses the oracle (thin-side rebate included), |price-oracle| <=
/// max_total, and total fee term within [fee_lo, fee_hi] when base=impact=skew=0.
#[test]
fn p2_kind2_never_crosses_oracle_with_rebate_and_fee_clamped() {
    let mut rng = XorShiftRng::seed_from_u64(0xC0FFEE);
    let mut rebate_seen = 0;
    let mut fills = 0;
    for _case in 0..30 * scale() {
        let mut c = rand_core(&mut rng);
        let mut v = rand_v2(&mut rng);
        v.thin_rebate = rng.gen_range(0..=c.skew_mult);
        c.max_inv = 0;
        let mut e = kind2_env(c, v);
        let mut oracle = 1_000_000u64;
        for _ in 0..30 {
            let s = e.slot() + rng.gen_range(0..40);
            e.svm.warp_to_slot(s);
            oracle = ((oracle as i128) * (10_000 + rng.gen_range(-500i128..=500)) / 10_000).max(1000) as u64;
            let inv = e.inventory();
            let req = rng.gen_range(-3_000_000_000i128..3_000_000_000);
            if req == 0 {
                continue;
            }
            if let Ok(r) = e.call(oracle, req) {
                if r.size == 0 {
                    continue;
                }
                fills += 1;
                if req > 0 {
                    assert!(r.price >= oracle, "BUY BELOW ORACLE: price {} oracle {oracle} inv {inv} req {req} c={c:?} v={v:?}", r.price);
                } else {
                    assert!(r.price <= oracle, "SELL ABOVE ORACLE: price {} oracle {oracle} inv {inv} req {req} c={c:?} v={v:?}", r.price);
                }
                let dev = (r.price as i128 - oracle as i128).unsigned_abs();
                assert!(dev <= ceil_div(oracle as u128 * c.max_total as u128, BPS), "outside max_total");
                let reduces = (req > 0 && inv > 0) || (req < 0 && inv < 0);
                if reduces && dev < ceil_div(oracle as u128 * (c.base as u128 + v.fee_lo as u128), BPS) {
                    rebate_seen += 1;
                }
            }
        }
    }
    assert!(fills > 100, "vacuous fills {fills}");
    eprintln!("rebate-priced fills observed: {rebate_seen}");

    // fee clamp: base=0, k=0, skew=0 => total == adaptive fee, in [lo, hi]; oracle 1e6 so
    // total bps == (price - oracle)/100 exactly for buys.
    for (lo, hi, a, bden) in [(20u16, 130u16, 700u16, 160u16), (5, 5, 3000, 1), (0, 1000, 65535, 1)] {
        let c = Core { kind: 2, trading_fee: 0, base: 0, max_total: 9000, impact_k: 0, liq: 1, max_fill: u64::MAX as u128, max_inv: 0, skew_mult: 0 };
        let v = V2 { fee_lo: lo, fee_hi: hi, fee_cold: lo, vol_a: a, vol_b_den: bden, vol_alpha: 10_000, warmup: 0, move_cap: 255, vol_ref: 1, thin_rebate: 0, skew_cap: 0, rebate_cap: 0, ..default_v2() };
        let mut e = kind2_env(c, v);
        let mut oracle = 1_000_000u64;
        for i in 0..40 {
            let s = e.slot() + 1;
            e.svm.warp_to_slot(s);
            // violent alternating moves to drive sigma up
            let mk = if i % 2 == 0 { 1_000_000u64 } else { 1_200_000 };
            oracle = mk;
            let r = e.call(oracle, 1_000).expect("fee-only call");
            let total = (r.price - oracle) as u128 * BPS / oracle as u128;
            assert!(total >= lo as u128 && total <= hi as u128 + 1, "fee {total} outside [{lo},{hi}] at i={i}");
        }
    }
}

/// Fill is monotone (non-decreasing) in the requested size from a fixed pre-state, and
/// never exceeds the request (backtest finding #1, doc §6).
#[test]
fn p2_kind2_fill_monotone_in_request() {
    let mut rng = XorShiftRng::seed_from_u64(0x0707);
    let mut checked = 0;
    for _case in 0..25 * scale() {
        let c = rand_core(&mut rng);
        let v = rand_v2(&mut rng);
        let mut e = kind2_env(c, v);
        // walk to a random inventory
        for _ in 0..rng.gen_range(0..6) {
            let _ = e.call(1_000_000, rng.gen_range(-2_000_000_000i128..2_000_000_000));
        }
        let snap = e.ctx_bytes();
        for dir in [1i128, -1] {
            let mut prev = 0u128;
            let mut sizes: Vec<i128> = (0..14).map(|_| rng.gen_range(1..6_000_000_000i128)).collect();
            sizes.sort();
            for sz in sizes {
                e.restore(snap.clone());
                if let Ok(r) = e.call(1_000_000, dir * sz) {
                    let f = r.size.unsigned_abs();
                    assert!(f <= sz as u128);
                    assert!(f >= prev, "NON-MONOTONE: req {} filled {f} < smaller req filled {prev}; c={c:?} v={v:?}", dir * sz);
                    prev = f;
                    checked += 1;
                }
            }
        }
    }
    assert!(checked > 200, "vacuous: {checked}");
}

/// §7: skew is path-independent — splitting a trade never makes it cheaper; a round trip
/// from flat never nets the taker a rebate. Isolated: base=0, impact=0, fee const.
#[test]
fn p2_kind2_skew_split_never_cheaper_and_round_trip_nonnegative() {
    let mut rng = XorShiftRng::seed_from_u64(0x5911);
    for _case in 0..40 * scale() {
        let skew = rng.gen_range(1..800u16);
        let cap = rng.gen_range(1..400u16);
        let v = V2 { fee_lo: 0, fee_hi: 0, fee_cold: 0, thin_rebate: rng.gen_range(0..=skew), skew_cap: cap, rebate_cap: rng.gen_range(0..=cap), skew_ref: rng.gen_range(1_000_000..2_000_000_000), warmup: 0, max_mark_age: 0, ..default_v2() };
        let c = Core { kind: 2, trading_fee: 0, base: 0, max_total: 9000, impact_k: 0, liq: 1, max_fill: u64::MAX as u128, max_inv: 0, skew_mult: skew };
        let oracle = 100_000_000u64; // $100, e6: fine price granularity
        let f: i128 = rng.gen_range(2..3_000_000_000);
        let cost = |r: &Ret, o: u64| -> i128 { (r.price as i128 - o as i128) * r.size }; // taker's cost in e6·q
        // single
        let mut e = kind2_env(c, v);
        let snap = e.ctx_bytes();
        let one = e.call(oracle, f).unwrap();
        assert_eq!(one.size, f, "no clip expected");
        let c1 = cost(&one, oracle);
        // split in two
        e.restore(snap.clone());
        let a = e.call(oracle, f / 2).unwrap();
        let b = e.call(oracle, f - f / 2).unwrap();
        let c2 = cost(&a, oracle) + cost(&b, oracle);
        // rounding: each price is ceil'd to 1 e6 tick, so allow 2 ticks * size slack the other way only
        // Prices carry an INTEGER total_bps (ceil'd per trade), so the single trade can
        // over-round by < 1 bps of notional; allow exactly that (oracle*f/1e4 in e6·q).
        let one_bps = (oracle as i128) * f / 10_000 + 2 * f;
        if c2 < c1 { eprintln!("split cheaper by {} (= {:.3} bps of notional)", c1 - c2, (c1 - c2) as f64 * 1e4 / (oracle as f64 * f as f64)); }
        assert!(c2 + one_bps >= c1, "SPLIT CHEAPER: single {c1} split {c2} (f={f}, v={v:?}, skew={skew})");
        // round trip from flat: buy f then sell f
        e.restore(snap);
        let buy = e.call(oracle, f).unwrap();
        let sell = e.call(oracle, -f).unwrap();
        let rt = cost(&buy, oracle) + cost(&sell, oracle);
        assert!(rt >= 0, "ROUND TRIP NETS REBATE: {rt} (f={f} v={v:?} skew={skew})");
    }
}

/// §2 HEADROOM: fill clipped to lp_headroom_q; headroom 0 => zero-fill (size 0, PARTIAL_OK).
#[test]
fn p2_headroom_clips_and_zero_fills() {
    let mut e = kind2_env(tuned_core(), default_v2());
    let r = e.call_ext(1_000_000, 500_000_000, X_HEADROOM, 0, 0, 0).expect("headroom 0 is a zero-fill, not an error");
    assert_eq!(r.size, 0, "headroom 0 must zero-fill");
    assert!(r.flags & 2 != 0, "zero-fill must carry FLAG_PARTIAL_OK");
    let r = e.call_ext(1_000_000, 500_000_000, X_HEADROOM, 0, 0, 12_345).unwrap();
    assert!(r.size.unsigned_abs() <= 12_345 && r.size > 0, "fill {} must be clipped to headroom", r.size);
    let r = e.call_ext(1_000_000, -500_000_000, X_HEADROOM, 0, 0, 7).unwrap();
    assert!(r.size >= -7 && r.size < 0);
    // kinds 0/1 too ("applies to every matcher kind")
    for kind in [0u8, 1] {
        let mut e = Env::new();
        e.init(Core { kind, trading_fee: 5, base: 5, max_total: 200, impact_k: if kind == 1 { 10 } else { 0 }, liq: if kind == 1 { 1_000_000_000_000 } else { 0 }, max_fill: u64::MAX as u128, max_inv: 0, skew_mult: 0 }).unwrap();
        let r = e.call_ext(1_000_000, 1_000_000, X_HEADROOM, 0, 0, 0).unwrap_or_else(|err| panic!("kind {kind} v1 ctx must accept ext v1: {err:?}"));
        assert_eq!(r.size, 0, "kind {kind}: headroom 0 must zero-fill");
    }
}

/// §2 MARK_SLOT + §6: stale mark -> 8002; future mark -> 8003; exits allowed (LP-reducing
/// under STALE_ALLOW_REDUCING, clipped to |inventory|; TAKER_REDUCING unclipped).
#[test]
fn p2_stale_mark_refusal_and_exits_never_trapped() {
    let v = V2 { max_mark_age: 10, ..default_v2() };
    let mut e = kind2_env(tuned_core(), v);
    let now = e.slot();
    // fresh
    e.call_ext(1_000_000, 100_000_000, X_MARK_SLOT, 0, now, 0).expect("fresh mark fills");
    let inv = e.inventory();
    assert!(inv < 0, "taker buy must decrease LP inventory (FE.1)");
    // future
    let err = e.call_ext(1_000_000, 1_000, X_MARK_SLOT, 0, now + 1, 0).unwrap_err();
    assert_eq!(custom(&err), Some(8003), "future mark_slot: {err:?}");
    // stale: age 11 > 10
    e.svm.warp_to_slot(now + 11);
    let err = e.call_ext(1_000_000, 1_000_000, X_MARK_SLOT, 0, now, 0).unwrap_err();
    assert_eq!(custom(&err), Some(8002), "stale opening fill must be STALE_MARK: {err:?}");
    // boundary: age exactly 10 is not stale
    let err_or_ok = e.call_ext(1_000_000, 1_000_000, X_MARK_SLOT, 0, now + 1, 0);
    assert!(err_or_ok.is_ok(), "age == max_mark_age must still fill: {err_or_ok:?}");
    let inv = e.inventory();
    // LP-reducing (taker sells while LP short) under stale: allowed, clipped to |inv|
    e.svm.warp_to_slot(now + 40);
    let r = e.call_ext(1_000_000, -(inv.unsigned_abs() as i128) * 3, X_MARK_SLOT, 0, now, 0).expect("LP-reducing exit under stale mark must fill");
    assert!(r.size < 0 && r.size.unsigned_abs() <= inv.unsigned_abs(), "reducing exit must be clipped to |inv| (never flips): fill {} inv {inv}", r.size);
    // TAKER_REDUCING attested: a fill that GROWS the LP inventory still goes through
    let r = e.call_ext(1_000_000, 5_000, X_MARK_SLOT | X_TAKER_REDUCING, 0, now, 0).expect("taker-reducing exit under stale mark must fill");
    assert_eq!(r.size, 5_000, "taker-reducing exit unclipped");
}

/// §2 strictness: legacy bytes still rejected when ext is off/invalid.
#[test]
fn p2_ext_block_strictness() {
    let mut e = kind2_env(tuned_core(), default_v2());
    let now = e.slot();
    let ok = e.call_raw(1_000_000, 1_000, [0; 24]);
    assert!(ok.is_ok(), "all-zero legacy tail must be accepted: {ok:?}");
    let bad = |t: [u8; 24]| t;
    let mut cases: Vec<(&str, [u8; 24])> = Vec::new();
    let mut t = [0u8; 24];
    t[5] = 1; // ext_version 0 but a non-zero byte
    cases.push(("v0 nonzero payload", bad(t)));
    let mut t = [0u8; 24];
    t[0] = 2;
    cases.push(("ext_version 2", t));
    let mut t = [0u8; 24];
    t[0] = 1;
    t[1] = 0x20; // bit5
    cases.push(("unknown flag bit5", t));
    let mut t = [0u8; 24];
    t[0] = 1;
    t[2] = 50; // band without EXEC_BAND
    cases.push(("band without flag", t));
    let mut t = [0u8; 24];
    t[0] = 1;
    t[4..12].copy_from_slice(&now.to_le_bytes()); // mark_slot without flag
    cases.push(("mark_slot without flag", t));
    let mut t = [0u8; 24];
    t[0] = 1;
    t[12] = 9; // headroom without flag
    cases.push(("headroom without flag", t));
    let mut t = [0u8; 24];
    t[0] = 1;
    t[23] = 1; // reserved
    cases.push(("reserved nonzero", t));
    for (name, t) in cases {
        assert!(e.call_raw(1_000_000, 1_000, t).is_err(), "{name}: must be rejected");
    }
}

/// §2 EXEC_BAND (P1 default 500 bps, and tighter): every filled price within band, all
/// kinds, for generated inputs.
#[test]
fn p2_exec_band_respected_all_kinds() {
    let mut rng = XorShiftRng::seed_from_u64(0xBA4D);
    let mut fills = 0;
    for case in 0..45 * scale() {
        let kind = (case % 3) as u8;
        let mut e = Env::new();
        let c = if kind == 2 {
            Core { max_total: rng.gen_range(100..2000), ..rand_core(&mut rng) }
        } else {
            Core { kind, trading_fee: rng.gen_range(0..300), base: rng.gen_range(0..300), max_total: rng.gen_range(600..3000), impact_k: if kind == 1 { rng.gen_range(1..2000) } else { 0 }, liq: if kind == 1 { rng.gen_range(1_000_000..100_000_000_000) } else { 0 }, max_fill: u64::MAX as u128, max_inv: 0, skew_mult: rng.gen_range(0..1000) }
        };
        if kind == 2 {
            e.init(Core { kind: 0, ..c }).unwrap();
            e.set_params(c, Some(rand_v2(&mut rng))).unwrap();
        } else {
            e.init(c).unwrap();
        }
        let band: u16 = [500u16, 100, 37, 1][rng.gen_range(0..4)];
        for _ in 0..12 {
            let oracle = rng.gen_range(1_000..50_000_000u64);
            let req = rng.gen_range(-5_000_000_000i128..5_000_000_000);
            if req == 0 {
                continue;
            }
            match e.call_ext(oracle, req, X_EXEC_BAND, band, 0, 0) {
                Ok(r) if r.size != 0 => {
                    fills += 1;
                    let dev = (r.price as i128 - oracle as i128).unsigned_abs();
                    let lim = ceil_div(oracle as u128 * band as u128, BPS);
                    assert!(dev <= lim, "kind {kind}: price {} outside band {band} of {oracle} (dev {dev} > {lim}) c={c:?}", r.price);
                }
                Ok(_) => {}
                Err(err) => panic!("kind {kind}: banded call must clip, not error: {err:?}"),
            }
        }
    }
    assert!(fills > 100, "vacuous: {fills}");
}
