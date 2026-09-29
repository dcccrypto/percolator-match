//! Market simulation driving the real `percolator_match::vamm::execute_leg` / `apply_fill`.

use crate::rng::{seed_from, Rng};
use percolator_match::v2::CallExt;
use percolator_match::vamm::{apply_fill, execute_leg, LegOut, MatcherCtx};
use percolator_match::{MatcherCall, ORACLE_PRICE_E6_MAX};
use solana_program::program_error::ProgramError;
use std::collections::BTreeMap;

pub const SLOT_S: f64 = 0.4;
pub const SLOT0: u64 = 300_000_000;
pub const WRAPPER_FEE_BPS: f64 = 10.0;
pub const SLOTS_PER_MIN: usize = 150;
pub const P1_EXEC_BAND_BPS: u16 = 500;

/// How a filled trade settles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// v18.2 actual: the position enters at the mark handed to the matcher; the matcher's
    /// exec price only gates limit checks. exec_size (clips/zero-fills/refusals) is real.
    A,
    /// Hypothetical settle-at-exec (needs a wrapper change): the quoted spread is LP revenue.
    B,
}

impl Mode {
    pub fn tag(self) -> &'static str {
        match self {
            Mode::A => "A",
            Mode::B => "B",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mix {
    pub benign: bool,
    pub arb: bool,
    pub momentum: bool,
}

impl Mix {
    pub const BENIGN: Mix = Mix {
        benign: true,
        arb: false,
        momentum: false,
    };
    pub const ARB: Mix = Mix {
        benign: false,
        arb: true,
        momentum: false,
    };
    pub const BENIGN_ARB: Mix = Mix {
        benign: true,
        arb: true,
        momentum: false,
    };
    pub const ALL: Mix = Mix {
        benign: true,
        arb: true,
        momentum: true,
    };
    pub fn name(&self) -> &'static str {
        match (self.benign, self.arb, self.momentum) {
            (true, false, false) => "benign",
            (false, true, false) => "arb",
            (true, true, false) => "benign+arb",
            (true, true, true) => "benign+arb+mom",
            _ => "custom",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Scenario {
    pub push_interval_s: f64,
    /// Keeper frozen for [start_s, end_s).
    pub outage: Option<(f64, f64)>,
    /// P1 wrapper: pass CallExt{mark_slot: Some(last push slot)}.
    pub p1: bool,
    pub mix: Mix,
    pub benign_per_min: f64,
    pub mode: Mode,
    pub arb_budget_usd: f64,
    pub arb_threshold_bps: f64,
    /// Arb repeats max_fill-sized calls within one slot up to its budget.
    pub arb_split: bool,
    pub momentum_usd: f64,
    pub momentum_every_s: f64,
    /// Benign/momentum limit price = mark * (1 ± this), Mode A only (arb sends no limit).
    pub limit_bps: f64,
    /// Flow seed label (independent of the param set -> common random numbers).
    pub flow_label: String,
}

impl Scenario {
    pub fn base(mode: Mode, mix: Mix, flow_label: &str) -> Self {
        Scenario {
            push_interval_s: 1.5,
            outage: None,
            p1: true,
            mix,
            benign_per_min: 2.0,
            mode,
            arb_budget_usd: 5_000.0,
            arb_threshold_bps: 5.0,
            arb_split: false,
            momentum_usd: 300.0,
            momentum_every_s: 30.0,
            limit_bps: 100.0,
            flow_label: flow_label.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Actor {
    Benign,
    Arb,
    Momentum,
}

#[derive(Clone, Debug, Default)]
pub struct Metrics {
    pub lp_pnl_usd: f64,
    pub volume_usd: f64,
    pub max_dd_usd: f64,
    pub min_equity_usd: f64,
    pub max_inv_usd: f64,
    pub fills: u64,
    pub zero_fills: u64,
    pub partial_fills: u64,
    /// (actor, error Debug string) -> count. Arb counts are per-slot attempts.
    pub errors: BTreeMap<(Actor, String), u64>,
    pub limit_rejects_benign: u64,
    pub limit_rejects_momentum: u64,
    pub benign_attempts: u64,
    pub benign_fills: u64,
    pub benign_req_usd: f64,
    pub benign_filled_usd: f64,
    /// Σ notional * quoted spread (vs mark) over benign fills, in usd*bps.
    pub benign_quote_bps_x_usd: f64,
    /// Σ notional * all-in cost (settlement vs mark + wrapper fee), in usd*bps.
    pub benign_cost_bps_x_usd: f64,
    pub arb_pnl_usd: f64,
    pub arb_round_trips: u64,
    pub arb_fills: u64,
    pub momentum_fills: u64,
    pub spread_rev_usd: f64,
    pub instant_markout_usd: f64,
    pub wrapper_fees_usd: f64,
    /// Inventory revaluation from each fill's true price to the end price.
    pub reval_usd: f64,
    pub final_inv_q: i128,
}

impl Metrics {
    pub fn lp_pnl_bps(&self) -> f64 {
        if self.volume_usd > 0.0 {
            self.lp_pnl_usd / self.volume_usd * 1e4
        } else {
            0.0
        }
    }
    pub fn benign_cost_bps(&self) -> f64 {
        if self.benign_filled_usd > 0.0 {
            self.benign_cost_bps_x_usd / self.benign_filled_usd
        } else {
            f64::NAN
        }
    }
    pub fn benign_quote_bps(&self) -> f64 {
        if self.benign_filled_usd > 0.0 {
            self.benign_quote_bps_x_usd / self.benign_filled_usd
        } else {
            f64::NAN
        }
    }
    pub fn err_count(&self, actor: Option<Actor>, needle: &str) -> u64 {
        self.errors
            .iter()
            .filter(|((a, e), _)| actor.is_none_or(|x| x == *a) && e.contains(needle))
            .map(|(_, c)| *c)
            .sum()
    }
    pub fn err_total(&self, actor: Option<Actor>) -> u64 {
        self.err_count(actor, "")
    }
    pub fn err_string(&self) -> String {
        self.errors
            .iter()
            .map(|((a, e), c)| format!("{a:?}:{e}={c}"))
            .collect::<Vec<_>>()
            .join(";")
    }
}

#[derive(Clone, Copy, Debug)]
struct BenignOrder {
    slot_idx: usize,
    buy: bool,
    notional_usd: f64,
}

fn gen_benign(n_slots: usize, per_min: f64, seed: u64) -> Vec<BenignOrder> {
    let mut rng = Rng::new(seed);
    let rate_per_s = per_min / 60.0;
    let horizon = n_slots as f64 * SLOT_S;
    let mut t = 0.0;
    let mut v = Vec::new();
    if rate_per_s <= 0.0 {
        return v;
    }
    loop {
        t += rng.exp(rate_per_s);
        if t >= horizon {
            break;
        }
        v.push(BenignOrder {
            slot_idx: (t / SLOT_S) as usize,
            buy: rng.coin(),
            notional_usd: 150.0 * rng.normal().exp(),
        });
    }
    v
}

pub fn price_e6(p: f64) -> u64 {
    (p * 1e6).round().max(1.0) as u64
}

/// q for a USD notional at price_e6: q = usd * 1e12 / price_e6.
fn q_for_usd(usd: f64, pe6: u64) -> u128 {
    (usd * 1e12 / pe6 as f64).floor().max(0.0) as u128
}

/// Integer limit price in e6, rounded in the taker's favour (UI-style slippage bound).
/// Exact integer arithmetic (a float `ceil(1400 * 1.01)` is 1415, not 1414).
fn limit_px(mark: u64, buy: bool, limit_bps: u64) -> f64 {
    let m = mark as u128;
    let l = limit_bps as u128;
    let v = if buy {
        (m * (10_000 + l)).div_ceil(10_000)
    } else {
        m * (10_000 - l.min(10_000)) / 10_000
    };
    v as f64
}

fn usd(q: i128, pe6: u64) -> f64 {
    q as f64 * pe6 as f64 / 1e12
}

/// One matcher call, committed to `ctx` only if the (simulated) transaction succeeds.
/// `limit` = Some(max acceptable exec price for a buy / min for a sell).
enum CallRes {
    Err,
    ZeroFill,
    LimitReject,
    Fill(LegOut),
}

struct Sim<'a> {
    ctx: MatcherCtx,
    sc: &'a Scenario,
    m: Metrics,
    req_id: u64,
    lp_cash_e12: i128,
    lp_inv: i128,
    sum_s_ptrue_e12: i128,
}

impl<'a> Sim<'a> {
    /// P1 wrapper: fresh-mark slot + P1's default exec band (500 bps); `taker_reducing`
    /// only for the arb's exits (the wrapper attests the taker is closing its own position).
    fn ext(&self, mark_slot: u64, taker_reducing: bool) -> CallExt {
        if self.sc.p1 {
            CallExt {
                mark_slot: Some(mark_slot),
                exec_band_bps: Some(P1_EXEC_BAND_BPS),
                taker_reducing,
                ..CallExt::default()
            }
        } else {
            CallExt::default()
        }
    }

    /// Price a call against a copy of `ctx` (no commit). Mirrors process_call's input checks.
    fn price(
        ctx: &mut MatcherCtx,
        req_id: u64,
        oracle: u64,
        size: i128,
        ext: &CallExt,
        slot: u64,
    ) -> Result<LegOut, ProgramError> {
        if oracle == 0 || oracle > ORACLE_PRICE_E6_MAX || size == i128::MIN {
            return Err(ProgramError::InvalidInstructionData);
        }
        let call = MatcherCall {
            req_id,
            asset_index: 0,
            lp_account_id: 1,
            oracle_price_e6: oracle,
            req_size: size,
        };
        let out = execute_leg(ctx, &call, ext, Some(slot), 0)?;
        apply_fill(ctx, &out, oracle)?;
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    fn trade(
        &mut self,
        actor: Actor,
        size: i128,
        mark: u64,
        mark_slot: u64,
        slot: u64,
        true_p: u64,
        limit: Option<f64>,
        taker_reducing: bool,
    ) -> CallRes {
        self.req_id += 1;
        let ext = self.ext(mark_slot, taker_reducing);
        let mut c = self.ctx;
        let out = match Self::price(&mut c, self.req_id, mark, size, &ext, slot) {
            Ok(o) => o,
            Err(e) => {
                *self.m.errors.entry((actor, format!("{e:?}"))).or_insert(0) += 1;
                return CallRes::Err;
            }
        };
        if out.exec_size == 0 {
            // Successful zero-fill: the matcher call succeeded, state (estimator /
            // observed tracker) commits.
            self.ctx = c;
            self.m.zero_fills += 1;
            return CallRes::ZeroFill;
        }
        if let Some(l) = limit {
            let px = out.exec_price_e6 as f64;
            let bad = if out.exec_size > 0 { px > l } else { px < l };
            if bad {
                match actor {
                    Actor::Benign => self.m.limit_rejects_benign += 1,
                    Actor::Momentum => self.m.limit_rejects_momentum += 1,
                    Actor::Arb => {}
                }
                return CallRes::LimitReject; // tx reverts: nothing commits
            }
        }
        self.ctx = c;
        let settle = match self.sc.mode {
            Mode::A => mark,
            Mode::B => out.exec_price_e6,
        };
        let s = out.exec_size;
        // LP is the counterparty: taker buys s>0 -> LP sells s, receives s*settle.
        self.lp_cash_e12 += s * settle as i128;
        self.lp_inv -= s;
        self.sum_s_ptrue_e12 += s * true_p as i128;
        assert_eq!(
            self.lp_inv, self.ctx.inventory_base,
            "inventory identity broken (harness vs ctx)"
        );
        let notional = usd(s.abs(), settle);
        self.m.volume_usd += notional;
        self.m.fills += 1;
        if s.unsigned_abs() < size.unsigned_abs() {
            self.m.partial_fills += 1;
        }
        self.m.spread_rev_usd += usd(s, settle) - usd(s, mark);
        self.m.instant_markout_usd += usd(s, mark) - usd(s, true_p);
        self.m.wrapper_fees_usd += notional * WRAPPER_FEE_BPS / 1e4;
        CallRes::Fill(out)
    }
}

/// Run one simulation. `prices` are per-second USD prices.
pub fn run(prices: &[f64], ctx0: MatcherCtx, sc: &Scenario) -> Result<Metrics, String> {
    ctx0.validate()
        .map_err(|e| format!("initial ctx invalid: {e:?}"))?;
    let pe6: Vec<u64> = prices.iter().map(|&p| price_e6(p)).collect();
    let n_slots = prices.len() * 5 / 2;
    let benign = if sc.mix.benign {
        gen_benign(n_slots, sc.benign_per_min, seed_from(&sc.flow_label, 1))
    } else {
        Vec::new()
    };
    let mut bi = 0usize;

    let mut sim = Sim {
        ctx: ctx0,
        sc,
        m: Metrics {
            min_equity_usd: 0.0,
            ..Default::default()
        },
        req_id: 0,
        lp_cash_e12: 0,
        lp_inv: 0,
        sum_s_ptrue_e12: 0,
    };
    let max_fill = ctx0.max_fill_abs;

    let mut mark = pe6[0];
    let mut mark_slot = SLOT0;
    let mut push_count: u64 = 0;
    let mut next_push = sc.push_interval_s;

    // Arb state (taker-perspective position).
    let mut arb_pos: i128 = 0;
    let mut arb_entry_push = 0u64;
    let mut arb_cash_e12: i128 = 0;
    let mut arb_fees = 0.0f64;

    let mom_every = (sc.momentum_every_s / SLOT_S).round().max(1.0) as usize;
    let mom_look = 300usize; // seconds

    let mut peak_eq = 0.0f64;
    let limit_bps = sc.limit_bps.round().max(0.0) as u64;

    for i in 0..n_slots {
        let t = i as f64 * SLOT_S;
        let sec = (i * 2) / 5;
        let p = pe6[sec];
        let slot = SLOT0 + i as u64;

        // Keeper push.
        if t + 1e-9 >= next_push {
            let frozen = sc.outage.is_some_and(|(a, b)| t >= a && t < b);
            if !frozen {
                mark = p;
                mark_slot = slot;
                push_count += 1;
            }
            while next_push <= t + 1e-9 {
                next_push += sc.push_interval_s;
            }
        }

        // Toxic latency arb. `arb_split`: repeat max_fill-sized calls in the same slot until
        // the budget is used / the edge is gone (per-fill caps are not a per-slot limit).
        if sc.mix.arb {
            let iters = if sc.arb_split { 64 } else { 1 };
            if arb_pos != 0 && push_count > arb_entry_push {
                for _ in 0..iters {
                    if arb_pos == 0 {
                        break;
                    }
                    let size = -arb_pos;
                    match sim.trade(Actor::Arb, size, mark, mark_slot, slot, p, None, true) {
                        CallRes::Fill(o) => {
                            let settle = if sc.mode == Mode::A {
                                mark
                            } else {
                                o.exec_price_e6
                            };
                            arb_cash_e12 -= o.exec_size * settle as i128;
                            arb_fees += usd(o.exec_size.abs(), settle) * WRAPPER_FEE_BPS / 1e4;
                            arb_pos += o.exec_size;
                            sim.m.arb_fills += 1;
                            if arb_pos == 0 {
                                sim.m.arb_round_trips += 1;
                            }
                        }
                        _ => break,
                    }
                }
            }
            if arb_pos == 0 {
                let gap_bps = (p as f64 - mark as f64) / mark as f64 * 1e4;
                if gap_bps.abs() > 2.0 * WRAPPER_FEE_BPS + sc.arb_threshold_bps {
                    let buy = gap_bps > 0.0;
                    let budget_q = q_for_usd(sc.arb_budget_usd, p);
                    for _ in 0..iters {
                        let used = arb_pos.unsigned_abs();
                        let q = budget_q.saturating_sub(used).min(max_fill);
                        if q == 0 {
                            break;
                        }
                        let size = if buy { q as i128 } else { -(q as i128) };
                        let ext = sim.ext(mark_slot, false);
                        let mut probe = sim.ctx;
                        let o1 =
                            match Sim::price(&mut probe, sim.req_id + 1, mark, size, &ext, slot) {
                                Err(e) => {
                                    *sim.m
                                        .errors
                                        .entry((Actor::Arb, format!("{e:?}")))
                                        .or_insert(0) += 1;
                                    break;
                                }
                                Ok(o1) if o1.exec_size == 0 => break,
                                Ok(o1) => o1,
                            };
                        let edge = match sc.mode {
                            Mode::A => gap_bps.abs() - 2.0 * WRAPPER_FEE_BPS,
                            Mode::B => {
                                let x1 = o1.exec_price_e6 as f64;
                                let entry = if buy {
                                    (p as f64 - x1) / x1 * 1e4
                                } else {
                                    (x1 - p as f64) / x1 * 1e4
                                };
                                let mut p2 = probe;
                                let exit_spread = match Sim::price(
                                    &mut p2,
                                    sim.req_id + 2,
                                    mark,
                                    -o1.exec_size,
                                    &ext,
                                    slot,
                                ) {
                                    Ok(o2) if o2.exec_size != 0 => {
                                        (o2.exec_price_e6 as f64 - mark as f64).abs() / mark as f64
                                            * 1e4
                                    }
                                    _ => sim.ctx.max_total_bps as f64,
                                };
                                entry - WRAPPER_FEE_BPS - (exit_spread + WRAPPER_FEE_BPS)
                            }
                        };
                        if edge <= sc.arb_threshold_bps {
                            break;
                        }
                        match sim.trade(Actor::Arb, size, mark, mark_slot, slot, p, None, false) {
                            CallRes::Fill(o) => {
                                let settle = if sc.mode == Mode::A {
                                    mark
                                } else {
                                    o.exec_price_e6
                                };
                                arb_cash_e12 -= o.exec_size * settle as i128;
                                arb_fees += usd(o.exec_size.abs(), settle) * WRAPPER_FEE_BPS / 1e4;
                                arb_pos += o.exec_size;
                                arb_entry_push = push_count;
                                sim.m.arb_fills += 1;
                            }
                            _ => break,
                        }
                    }
                }
            }
        }

        // Benign flow.
        while bi < benign.len() && benign[bi].slot_idx == i {
            let o = benign[bi];
            bi += 1;
            let q = q_for_usd(o.notional_usd, mark).min(max_fill);
            sim.m.benign_attempts += 1;
            let req_usd = usd(q as i128, mark);
            sim.m.benign_req_usd += req_usd;
            if q == 0 {
                continue;
            }
            let size = if o.buy { q as i128 } else { -(q as i128) };
            let limit = (sc.mode == Mode::A).then(|| limit_px(mark, o.buy, limit_bps));
            if let CallRes::Fill(out) =
                sim.trade(Actor::Benign, size, mark, mark_slot, slot, p, limit, false)
            {
                let settle = if sc.mode == Mode::A {
                    mark
                } else {
                    out.exec_price_e6
                };
                let n = usd(out.exec_size.abs(), settle);
                let quote = (out.exec_price_e6 as f64 - mark as f64).abs() / mark as f64 * 1e4;
                let paid = (settle as f64 - mark as f64).abs() / mark as f64 * 1e4;
                sim.m.benign_fills += 1;
                sim.m.benign_filled_usd += n;
                sim.m.benign_quote_bps_x_usd += n * quote;
                sim.m.benign_cost_bps_x_usd += n * (paid + WRAPPER_FEE_BPS);
            }
        }

        // Momentum trender.
        if sc.mix.momentum && sec >= mom_look && i % mom_every == 0 {
            let past = pe6[sec - mom_look];
            if p != past {
                let buy = p > past;
                let q = q_for_usd(sc.momentum_usd, mark).min(max_fill);
                if q > 0 {
                    let size = if buy { q as i128 } else { -(q as i128) };
                    let limit = (sc.mode == Mode::A).then(|| limit_px(mark, buy, limit_bps));
                    if let CallRes::Fill(_) = sim.trade(
                        Actor::Momentum,
                        size,
                        mark,
                        mark_slot,
                        slot,
                        p,
                        limit,
                        false,
                    ) {
                        sim.m.momentum_fills += 1;
                    }
                }
            }
        }

        // Minute equity mark (at TRUE price).
        if i % SLOTS_PER_MIN == 0 || i + 1 == n_slots {
            let eq = sim.lp_cash_e12 as f64 / 1e12 + usd(sim.lp_inv, p);
            peak_eq = peak_eq.max(eq);
            sim.m.max_dd_usd = sim.m.max_dd_usd.max(peak_eq - eq);
            sim.m.min_equity_usd = sim.m.min_equity_usd.min(eq);
            sim.m.max_inv_usd = sim.m.max_inv_usd.max(usd(sim.lp_inv.abs(), p));
        }
    }

    sim.ctx
        .validate()
        .map_err(|e| format!("final ctx invalid: {e:?}"))?;
    let p_end = *pe6.last().unwrap();
    sim.m.lp_pnl_usd = sim.lp_cash_e12 as f64 / 1e12 + usd(sim.lp_inv, p_end);
    sim.m.arb_pnl_usd = arb_cash_e12 as f64 / 1e12 + usd(arb_pos, p_end) - arb_fees;
    sim.m.final_inv_q = sim.lp_inv;
    sim.m.reval_usd = sim.sum_s_ptrue_e12 as f64 / 1e12 - usd(-sim.lp_inv, p_end);
    Ok(sim.m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{build_ctx, Spec, V2Mode};

    fn zero_spread() -> Spec {
        Spec {
            name: "zero".into(),
            kind: 0,
            trading_fee_bps: 0,
            base_spread_bps: 0,
            max_total_bps: 0,
            impact_k_bps: 0,
            liq_mult_capital: 0.0,
            skew_mult_bps: 0,
            max_fill_div: 4,
            v2: V2Mode::None,
        }
    }

    #[test]
    fn limit_is_exact_integer() {
        assert_eq!(limit_px(1400, true, 100), 1414.0);
        assert_eq!(limit_px(1400, false, 100), 1386.0);
        assert_eq!(limit_px(1401, true, 100), 1416.0); // ceil(1415.01)
    }

    #[test]
    fn constant_price_zero_spread_is_exactly_zero() {
        let prices = vec![50.0; 4 * 3600];
        let ctx = build_ctx(&zero_spread(), price_e6(50.0)).unwrap();
        for mode in [Mode::A, Mode::B] {
            let mut sc = Scenario::base(mode, Mix::BENIGN, "t0");
            sc.benign_per_min = 10.0;
            let m = run(&prices, ctx, &sc).unwrap();
            assert!(m.fills > 100);
            assert_eq!(m.lp_pnl_usd, 0.0);
            assert_eq!(m.spread_rev_usd, 0.0);
        }
    }

    /// Zero-spread LP vs zero-edge flow on a random walk with a live mark == true price at
    /// every trade (push every slot): E[PnL] = 0. Check the mean over seeds is within 4 SE.
    #[test]
    fn zero_edge_flow_has_zero_expected_pnl() {
        let ctx = build_ctx(&zero_spread(), price_e6(100.0)).unwrap();
        let mut pnls = Vec::new();
        for seed in 0..40u64 {
            let mut r = Rng::new(1000 + seed);
            let mut p = 100.0f64;
            let prices: Vec<f64> = (0..3600)
                .map(|_| {
                    p *= (0.0005 * r.normal()).exp();
                    p
                })
                .collect();
            let mut sc = Scenario::base(Mode::B, Mix::BENIGN, &format!("zero-edge-{seed}"));
            sc.push_interval_s = SLOT_S; // mark always current
            sc.benign_per_min = 20.0;
            pnls.push(run(&prices, ctx, &sc).unwrap().lp_pnl_usd);
        }
        let n = pnls.len() as f64;
        let mean = pnls.iter().sum::<f64>() / n;
        let sd = (pnls.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0)).sqrt();
        assert!(sd > 0.0);
        assert!(mean.abs() < 4.0 * sd / n.sqrt(), "mean {mean} sd {sd}");
    }

    /// Cash + inventory identity: PnL = spread revenue + instant markout + inventory
    /// revaluation, and the harness inventory equals ctx.inventory_base (asserted inside).
    #[test]
    fn pnl_decomposition_identity() {
        let mut r = Rng::new(9);
        let mut p = 2.0f64;
        let prices: Vec<f64> = (0..7200)
            .map(|_| {
                p *= (0.001 * r.normal()).exp();
                p
            })
            .collect();
        let ctx = build_ctx(&Spec::v2_default(), price_e6(prices[0])).unwrap();
        for mode in [Mode::A, Mode::B] {
            let sc = Scenario::base(mode, Mix::ALL, "ident");
            let m = run(&prices, ctx, &sc).unwrap();
            assert!(m.fills > 0);
            let sum = m.spread_rev_usd + m.instant_markout_usd + m.reval_usd;
            assert!(
                (sum - m.lp_pnl_usd).abs() < 1e-6,
                "{sum} vs {}",
                m.lp_pnl_usd
            );
            if mode == Mode::A {
                assert_eq!(m.spread_rev_usd, 0.0);
            } else {
                assert!(m.spread_rev_usd > 0.0);
            }
        }
    }

    #[test]
    fn stale_refusal_counted_in_outage() {
        let mut p = 10.0f64;
        let prices: Vec<f64> = (0..3600)
            .map(|i| {
                if (1000..1600).contains(&i) {
                    p *= 1.0002;
                }
                p
            })
            .collect();
        let ctx = build_ctx(&Spec::v2_default(), price_e6(10.0)).unwrap();
        let mut sc = Scenario::base(Mode::B, Mix::BENIGN_ARB, "outage");
        sc.outage = Some((1000.0, 1600.0));
        sc.benign_per_min = 10.0;
        let m = run(&prices, ctx, &sc).unwrap();
        assert!(m.err_count(None, "Custom(8002)") > 0, "{}", m.err_string());
    }

    /// Probe of the REAL pricing code: exec price is monotone in the FILLED size (buys
    /// non-decreasing, sells non-increasing) across inventories, kinds and price scales, and
    /// extreme sizes return Ok/Err without panicking. (Monotone in filled size, not in
    /// requested size: kind 2's size clip can hand a LARGER request a SMALLER fill — see
    /// `-- probe` and RESULTS.md.)
    #[test]
    fn quote_monotone_in_size_and_no_panic() {
        use crate::params::{default_knobs, V2Knobs};
        let tuned = V2Knobs {
            fee_lo: 10,
            fee_hi: 80,
            fee_cold: Some(10),
            ..default_knobs()
        };
        let mut specs = vec![Spec::v1_deployed(), Spec::v1_kind1(), Spec::v2_default()];
        let mut t = Spec::v2_custom("t", tuned, 300, 5000);
        t.max_total_bps = 100;
        specs.push(t);
        for spec in &specs {
            for &px in &[1_400u64, 8_000, 170_000, 75_000_000] {
                let ctx0 = build_ctx(spec, px).unwrap();
                let max_inv = ctx0.max_inventory_abs as i128;
                for k in -4i128..=4 {
                    let mut ctx = ctx0;
                    ctx.inventory_base = max_inv * k / 4;
                    for ext in [
                        CallExt::default(),
                        CallExt {
                            mark_slot: Some(SLOT0),
                            exec_band_bps: Some(500),
                            ..CallExt::default()
                        },
                    ] {
                        for buy in [true, false] {
                            let mut pts: Vec<(u128, u64)> = Vec::new();
                            let mut q: i128 = 1;
                            while q < ctx.max_fill_abs as i128 * 2 {
                                let size = if buy { q } else { -q };
                                let mut c = ctx;
                                if let Ok(o) = Sim::price(&mut c, 1, px, size, &ext, SLOT0) {
                                    if o.exec_size != 0 {
                                        pts.push((o.exec_size.unsigned_abs(), o.exec_price_e6));
                                    }
                                }
                                q = q * 3 / 2 + 1;
                            }
                            pts.sort();
                            for w in pts.windows(2) {
                                let ok = if buy {
                                    w[1].1 >= w[0].1
                                } else {
                                    w[1].1 <= w[0].1
                                };
                                assert!(
                                    ok,
                                    "{} px {px} inv {} {:?}",
                                    spec.name, ctx.inventory_base, w
                                );
                            }
                            for size in [i128::MAX / 2, -(i128::MAX / 2), i128::MAX, -i128::MAX] {
                                let mut c = ctx;
                                let _ = Sim::price(&mut c, 1, px, size, &ext, SLOT0);
                            }
                        }
                    }
                }
            }
        }
    }
}
