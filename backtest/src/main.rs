//! Offline LP backtest for percolator-match v2.
//!
//! cargo run --release --manifest-path backtest/Cargo.toml -- [all|bench] [--quick] [--sweep full|coord]

mod params;
mod rng;
mod sim;
mod tape;

use params::{build_ctx, default_knobs, Spec, V2Knobs, V2Mode};
use sim::{run, Metrics, Mix, Mode, Scenario};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;
use tape::{largest_move_window, Tape};

fn par_map<T: Sync, R: Send>(items: &[T], f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let n = std::thread::available_parallelism()
        .map(|x| x.get())
        .unwrap_or(4);
    let next = AtomicUsize::new(0);
    let out: Mutex<Vec<(usize, R)>> = Mutex::new(Vec::with_capacity(items.len()));
    std::thread::scope(|s| {
        for _ in 0..n {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                if i >= items.len() {
                    break;
                }
                let r = f(&items[i]);
                out.lock().unwrap().push((i, r));
            });
        }
    });
    let mut v = out.into_inner().unwrap();
    v.sort_by_key(|x| x.0);
    v.into_iter().map(|x| x.1).collect()
}

#[derive(Clone, Debug)]
struct Job {
    tape: usize,
    spec: Spec,
    sc: Scenario,
    push_label: String,
}

#[derive(Clone, Debug)]
struct Row {
    tape: String,
    in_sample: bool,
    spec: String,
    mode: Mode,
    mix: String,
    rate: f64,
    push: String,
    p1: bool,
    m: Metrics,
}

fn flow_label(t: &Tape, mix: Mix, rate: f64, push: &str) -> String {
    format!("{}|{}|{}|{}", t.label(), mix.name(), rate, push)
}

#[allow(clippy::too_many_arguments)]
fn make_job(
    tapes: &[Tape],
    ti: usize,
    spec: &Spec,
    mode: Mode,
    mix: Mix,
    rate: f64,
    push: &str,
    p1: bool,
) -> Job {
    let t = &tapes[ti];
    let mut sc = Scenario::base(mode, mix, &flow_label(t, mix, rate, push));
    sc.benign_per_min = rate;
    sc.p1 = p1;
    match push {
        "1.5s" => sc.push_interval_s = 1.5,
        "7s" => sc.push_interval_s = 7.0,
        "outage" => {
            sc.push_interval_s = 1.5;
            let s = largest_move_window(&t.prices, 600) as f64;
            sc.outage = Some((s, s + 600.0));
        }
        other => panic!("unknown push scenario {other}"),
    }
    Job {
        tape: ti,
        spec: spec.clone(),
        sc,
        push_label: push.into(),
    }
}

fn exec_jobs(tapes: &[Tape], jobs: &[Job]) -> Vec<Row> {
    let res = par_map(jobs, |j| {
        let t = &tapes[j.tape];
        let ctx = build_ctx(&j.spec, sim::price_e6(t.prices[0]))
            .unwrap_or_else(|e| panic!("{}: {e}", t.label()));
        let m = run(&t.prices, ctx, &j.sc)
            .unwrap_or_else(|e| panic!("{} {}: {e}", t.label(), j.spec.name));
        Row {
            tape: t.label(),
            in_sample: t.in_sample,
            spec: j.spec.name.clone(),
            mode: j.sc.mode,
            mix: j.sc.mix.name().into(),
            rate: j.sc.benign_per_min,
            push: j.push_label.clone(),
            p1: j.sc.p1,
            m,
        }
    });
    res
}

fn csv_header() -> &'static str {
    "tape,in_sample,params,mode,mix,benign_per_min,push,p1,lp_pnl_usd,volume_usd,lp_pnl_bps,\
max_dd_usd,min_equity_usd,max_inv_usd,fills,zero_fills,partial_fills,refusals_total,\
refusals_benign,refusals_arb_slot_attempts,refusals_momentum,stale_8002,limit_rejects_benign,\
limit_rejects_momentum,benign_attempts,benign_fills,benign_fill_ratio,benign_quote_bps,\
benign_cost_bps,arb_pnl_usd,arb_round_trips,momentum_fills,spread_rev_usd,instant_markout_usd,\
reval_usd,wrapper_fees_usd,errors"
}

fn csv_row(r: &Row) -> String {
    let m = &r.m;
    let fr = if m.benign_req_usd > 0.0 {
        m.benign_filled_usd / m.benign_req_usd
    } else {
        f64::NAN
    };
    format!(
        "{},{},{},{},{},{},{},{},{:.2},{:.2},{:.2},{:.2},{:.2},{:.2},{},{},{},{},{},{},{},{},{},{},{},{},{:.4},{:.2},{:.2},{:.2},{},{},{:.2},{:.2},{:.2},{:.2},\"{}\"",
        r.tape,
        r.in_sample,
        r.spec,
        r.mode.tag(),
        r.mix,
        r.rate,
        r.push,
        r.p1,
        m.lp_pnl_usd,
        m.volume_usd,
        m.lp_pnl_bps(),
        m.max_dd_usd,
        m.min_equity_usd,
        m.max_inv_usd,
        m.fills,
        m.zero_fills,
        m.partial_fills,
        m.err_total(None),
        m.err_total(Some(sim::Actor::Benign)),
        m.err_total(Some(sim::Actor::Arb)),
        m.err_total(Some(sim::Actor::Momentum)),
        m.err_count(None, "Custom(8002)"),
        m.limit_rejects_benign,
        m.limit_rejects_momentum,
        m.benign_attempts,
        m.benign_fills,
        fr,
        m.benign_quote_bps(),
        m.benign_cost_bps(),
        m.arb_pnl_usd,
        m.arb_round_trips,
        m.momentum_fills,
        m.spread_rev_usd,
        m.instant_markout_usd,
        m.reval_usd,
        m.wrapper_fees_usd,
        m.err_string()
    )
}

fn write_csv(path: &Path, rows: &[Row]) {
    let mut s = String::from(csv_header());
    s.push('\n');
    for r in rows {
        s.push_str(&csv_row(r));
        s.push('\n');
    }
    std::fs::write(path, s).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
}

// ---------------------------------------------------------------------------------------
// Parameter search
// ---------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct Cand {
    knobs: V2Knobs,
    skew: u16,
    impact_k: u32,
    liq_mult: f64,
    max_fill_div: u32,
    max_total: u32,
}

impl Cand {
    fn spec(&self, name: &str) -> Spec {
        let mut k = self.knobs;
        let room = self
            .max_total
            .saturating_sub(Spec::v2_default().base_spread_bps) as u16;
        k.fee_hi = k.fee_hi.min(room);
        k.fee_lo = k.fee_lo.min(k.fee_hi);
        let mut s = Spec::v2_custom(name, k, self.skew, self.impact_k);
        s.liq_mult_capital = self.liq_mult;
        s.max_fill_div = self.max_fill_div;
        s.max_total_bps = self.max_total;
        s
    }
    fn describe(&self) -> String {
        let k = &self.knobs;
        format!(
            "max_total={} fee_lo={} fee_hi={} fee_cold={} vol_a_milli={} vol_b_den={} vol_ref_slots={} skew_mult={} thin_rebate={} impact_k={} liq={}x_capital max_fill=max_inv/{} max_mark_age={} observed_stale={}",
            self.max_total,
            k.fee_lo,
            k.fee_hi.min(self.max_total.saturating_sub(20) as u16),
            k.fee_cold.map(|c| c.to_string()).unwrap_or("default(80,clamped)".into()),
            k.vol_a_milli,
            k.vol_b_den,
            k.vol_ref_slots,
            self.skew,
            if k.thin_rebate_half { self.skew / 2 } else { 0 },
            self.impact_k,
            self.liq_mult,
            self.max_fill_div,
            k.max_mark_age_slots,
            k.observed_stale_slots
        )
    }
}

#[derive(Clone, Debug)]
struct Score {
    worst_pnl: f64,
    sum_pnl: f64,
    benign_cost: f64,
    benign_fill_ratio: f64,
}

fn eval_cands(tapes: &[Tape], cands: &[Cand], mode: Mode) -> Vec<Score> {
    let ins: Vec<usize> = (0..tapes.len()).filter(|&i| tapes[i].in_sample).collect();
    let mut jobs = Vec::new();
    for (ci, c) in cands.iter().enumerate() {
        let spec = c.spec(&format!("cand{ci}"));
        for &ti in &ins {
            for push in ["1.5s", "7s"] {
                jobs.push(make_job(
                    tapes,
                    ti,
                    &spec,
                    mode,
                    Mix::BENIGN_ARB,
                    2.0,
                    push,
                    true,
                ));
            }
        }
    }
    let per = ins.len() * 2;
    let rows = exec_jobs(tapes, &jobs);
    rows.chunks(per)
        .map(|ch| {
            let worst = ch
                .iter()
                .map(|r| r.m.lp_pnl_usd)
                .fold(f64::INFINITY, f64::min);
            let sum = ch.iter().map(|r| r.m.lp_pnl_usd).sum();
            let n: f64 = ch.iter().map(|r| r.m.benign_filled_usd).sum();
            let c: f64 = ch.iter().map(|r| r.m.benign_cost_bps_x_usd).sum();
            let req: f64 = ch.iter().map(|r| r.m.benign_req_usd).sum();
            Score {
                worst_pnl: worst,
                sum_pnl: sum,
                benign_cost: if n > 0.0 { c / n } else { f64::INFINITY },
                benign_fill_ratio: if req > 0.0 { n / req } else { 0.0 },
            }
        })
        .collect()
}

fn full_grid_b() -> Vec<Cand> {
    let mut v = Vec::new();
    let skews: [(u16, bool); 5] = [
        (0, false),
        (100, false),
        (100, true),
        (300, false),
        (300, true),
    ];
    for fee_lo in [10u16, 20, 30, 50] {
        for fee_hi in [100u16, 150, 250] {
            for vol_a in [500u16, 1000, 1500] {
                for vol_b in [0u16, 100, 200] {
                    for vref in [4u16, 25] {
                        for &(skew, half) in &skews {
                            for impact in [0u32, 5000, 10000] {
                                v.push(Cand {
                                    knobs: V2Knobs {
                                        fee_lo,
                                        fee_hi,
                                        vol_a_milli: vol_a,
                                        vol_b_den: vol_b,
                                        vol_ref_slots: vref,
                                        thin_rebate_half: half,
                                        ..default_knobs()
                                    },
                                    skew,
                                    impact_k: impact,
                                    liq_mult: 10.0,
                                    max_fill_div: 4,
                                    max_total: 400,
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    v
}

fn pick_best(cands: &[Cand], scores: &[Score], feasible: impl Fn(&Score) -> bool) -> usize {
    let mut best: Option<usize> = None;
    for i in 0..cands.len() {
        if !feasible(&scores[i]) {
            continue;
        }
        best = match best {
            None => Some(i),
            Some(b) => {
                let (s, t) = (&scores[i], &scores[b]);
                if s.worst_pnl > t.worst_pnl + 1e-9
                    || ((s.worst_pnl - t.worst_pnl).abs() <= 1e-9 && s.sum_pnl > t.sum_pnl)
                {
                    Some(i)
                } else {
                    Some(b)
                }
            }
        };
    }
    best.expect("no feasible candidate")
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let quick = args.iter().any(|a| a == "--quick");
    let cmd = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .cloned()
        .unwrap_or("all".into());
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let out_dir = root.join("results");
    std::fs::create_dir_all(&out_dir).expect("mkdir results");
    let t0 = Instant::now();

    let mut tapes = tape::load_all(&root.join("data"), 0xB0B).unwrap_or_else(|e| panic!("{e}"));
    if quick {
        for t in tapes.iter_mut() {
            t.prices.truncate(6 * 3600);
        }
    }
    eprintln!(
        "loaded {} tapes in {:.1}s",
        tapes.len(),
        t0.elapsed().as_secs_f64()
    );

    if cmd == "probe" {
        // Reproducer for the kind-2 requested-size non-monotonicity (see RESULTS.md).
        use percolator_match::v2::CallExt;
        use percolator_match::vamm::execute_leg;
        use percolator_match::MatcherCall;
        let px = 1_400u64;
        let ctx0 = build_ctx(&Spec::v2_default(), px).expect("ctx");
        let mut ctx = ctx0;
        ctx.inventory_base = -(ctx0.max_inventory_abs as i128) / 2;
        println!(
            "V2-default @ oracle_price_e6={px}: max_fill_abs={} max_inventory_abs={} inventory_base={} liquidity_notional_e6={}",
            ctx.max_fill_abs, ctx.max_inventory_abs, ctx.inventory_base, ctx.liquidity_notional_e6
        );
        println!(
            "{:>16} {:>16} {:>10} {:>8}",
            "req_size(buy)", "exec_size", "exec_px", "bps"
        );
        let mut q: i128 = 1_000_000_000_000;
        while q <= ctx.max_fill_abs as i128 {
            let mut c = ctx;
            let call = MatcherCall {
                req_id: 1,
                asset_index: 0,
                lp_account_id: 1,
                oracle_price_e6: px,
                req_size: q,
            };
            match execute_leg(&mut c, &call, &CallExt::default(), Some(sim::SLOT0), 0) {
                Ok(o) => println!(
                    "{q:>16} {:>16} {:>10} {:>8.1}",
                    o.exec_size,
                    o.exec_price_e6,
                    (o.exec_price_e6 as f64 / px as f64 - 1.0) * 1e4
                ),
                Err(e) => println!("{q:>16} ERR {e:?}"),
            }
            q += 250_000_000_000;
        }
        return;
    }

    if cmd == "bench" {
        let j = make_job(
            &tapes,
            1,
            &Spec::v2_default(),
            Mode::B,
            Mix::ALL,
            10.0,
            "1.5s",
            true,
        );
        let t = Instant::now();
        let r = exec_jobs(&tapes, std::slice::from_ref(&j));
        eprintln!(
            "one run {:.3}s: {}",
            t.elapsed().as_secs_f64(),
            csv_row(&r[0])
        );
        return;
    }

    let mut md = String::new();

    // ---- 1. Mode B parameter search (spec objective) ----
    let t1 = Instant::now();
    let grid = full_grid_b();
    let scores = eval_cands(&tapes, &grid, Mode::B);
    let bi = pick_best(&grid, &scores, |s| s.benign_cost <= 60.0);
    let tuned_b = grid[bi].clone();
    {
        let mut s = String::from("idx,fee_lo,fee_hi,vol_a_milli,vol_b_den,vol_ref_slots,skew,thin_rebate,impact_k,worst_pnl_usd,sum_pnl_usd,benign_cost_bps,benign_fill_ratio,feasible\n");
        for (i, (c, sc)) in grid.iter().zip(&scores).enumerate() {
            let k = &c.knobs;
            let _ = writeln!(
                s,
                "{i},{},{},{},{},{},{},{},{},{:.2},{:.2},{:.2},{:.4},{}",
                k.fee_lo,
                k.fee_hi,
                k.vol_a_milli,
                k.vol_b_den,
                k.vol_ref_slots,
                c.skew,
                if k.thin_rebate_half { c.skew / 2 } else { 0 },
                c.impact_k,
                sc.worst_pnl,
                sc.sum_pnl,
                sc.benign_cost,
                sc.benign_fill_ratio,
                sc.benign_cost <= 60.0
            );
        }
        std::fs::write(out_dir.join("sweep_modeB.csv"), s).unwrap();
    }
    let feasible = scores.iter().filter(|s| s.benign_cost <= 60.0).count();
    let _ = writeln!(
        md,
        "## Mode B search\n\n{} candidates, {} feasible (benign all-in cost <= 60 bps). Chosen: `{}`\n\nin-sample worst ${:.2}, sum ${:.2}, benign cost {:.2} bps. Search time {:.1}s.\n",
        grid.len(),
        feasible,
        tuned_b.describe(),
        scores[bi].worst_pnl,
        scores[bi].sum_pnl,
        scores[bi].benign_cost,
        t1.elapsed().as_secs_f64()
    );
    // Top-10 feasible for the overfitting discussion.
    let mut order: Vec<usize> = (0..grid.len())
        .filter(|&i| scores[i].benign_cost <= 60.0)
        .collect();
    order.sort_by(|&a, &b| {
        scores[b]
            .worst_pnl
            .partial_cmp(&scores[a].worst_pnl)
            .unwrap()
    });
    let _ = writeln!(md, "Top 10 feasible (worst-case in-sample $):\n\n| rank | params | worst $ | sum $ | benign bps |\n|---|---|---|---|---|");
    for (r, &i) in order.iter().take(10).enumerate() {
        let _ = writeln!(
            md,
            "| {} | {} | {:.2} | {:.2} | {:.1} |",
            r + 1,
            grid[i].describe(),
            scores[i].worst_pnl,
            scores[i].sum_pnl,
            scores[i].benign_cost
        );
    }
    md.push('\n');
    eprintln!(
        "mode B search done {:.1}s: {}",
        t1.elapsed().as_secs_f64(),
        tuned_b.describe()
    );

    // ---- 2. Mode A search: size caps / impact / skew / stale guard ----
    let t2 = Instant::now();
    let mut grid_a = Vec::new();
    for impact in [0u32, 5000, 10000] {
        for liq in [2.0f64, 5.0, 10.0] {
            if impact == 0 && liq != 10.0 {
                continue;
            }
            for skew in [0u16, 100, 300] {
                for div in [4u32, 10, 40] {
                    for age in [150u16, 10] {
                        for (mt, cold_lo) in [(400u32, false), (100u32, true)] {
                            let mut c = tuned_b.clone();
                            c.max_total = mt;
                            if cold_lo {
                                c.knobs.fee_cold = Some(c.knobs.fee_lo);
                            }
                            c.impact_k = impact;
                            c.liq_mult = liq;
                            c.skew = skew;
                            c.knobs.thin_rebate_half = skew > 0;
                            c.max_fill_div = div;
                            c.knobs.max_mark_age_slots = age;
                            grid_a.push(c);
                        }
                    }
                }
            }
        }
    }
    let scores_a = eval_cands(&tapes, &grid_a, Mode::A);
    let ai = pick_best(&grid_a, &scores_a, |s| s.benign_fill_ratio >= 0.9);
    let tuned_a = grid_a[ai].clone();
    {
        let mut s =
            String::from("idx,params,worst_pnl_usd,sum_pnl_usd,benign_fill_ratio,feasible\n");
        for (i, (c, sc)) in grid_a.iter().zip(&scores_a).enumerate() {
            let _ = writeln!(
                s,
                "{i},\"{}\",{:.2},{:.2},{:.4},{}",
                c.describe(),
                sc.worst_pnl,
                sc.sum_pnl,
                sc.benign_fill_ratio,
                sc.benign_fill_ratio >= 0.9
            );
        }
        std::fs::write(out_dir.join("sweep_modeA.csv"), s).unwrap();
    }
    let _ = writeln!(
        md,
        "## Mode A search\n\n{} candidates. Chosen (max worst-case Mode-A LP PnL s.t. benign filled/requested notional >= 90%): `{}`\n\nin-sample worst ${:.2}, sum ${:.2}, benign fill ratio {:.3}. Search time {:.1}s.\n",
        grid_a.len(),
        tuned_a.describe(),
        scores_a[ai].worst_pnl,
        scores_a[ai].sum_pnl,
        scores_a[ai].benign_fill_ratio,
        t2.elapsed().as_secs_f64()
    );
    eprintln!(
        "mode A search done {:.1}s: {}",
        t2.elapsed().as_secs_f64(),
        tuned_a.describe()
    );

    // Exact configs of the tuned sets (as built for the SOL_calm tape).
    for (name, c) in [("V2-tuned-B", &tuned_b), ("V2-tuned-A", &tuned_a)] {
        let ctx = build_ctx(&c.spec(name), sim::price_e6(tapes[0].prices[0])).expect("tuned ctx");
        let _ = writeln!(
            md,
            "{name} ctx (SOL_calm open): kind={} trading_fee_bps={} base_spread_bps={} max_total_bps={} impact_k_bps={} liquidity_notional_e6={} skew_spread_mult_bps={} max_fill_abs={} max_inventory_abs={}\n\n`{:?}`\n",
            ctx.kind,
            ctx.trading_fee_bps,
            ctx.base_spread_bps,
            ctx.max_total_bps,
            ctx.impact_k_bps,
            ctx.liquidity_notional_e6,
            ctx.skew_spread_mult_bps,
            ctx.max_fill_abs,
            ctx.max_inventory_abs,
            ctx.v2_block().map(|b| b.cfg)
        );
    }

    // ---- 3. Main grid ----
    let t3 = Instant::now();
    let specs = vec![
        Spec::v1_deployed(),
        Spec::v1_kind1(),
        Spec::v2_default(),
        tuned_b.spec("V2-tuned-B"),
        tuned_a.spec("V2-tuned-A"),
    ];
    let mut jobs = Vec::new();
    for ti in 0..tapes.len() {
        for spec in &specs {
            for mode in [Mode::A, Mode::B] {
                for mix in [Mix::BENIGN, Mix::ARB, Mix::BENIGN_ARB, Mix::ALL] {
                    let rates: &[f64] = if mix.benign { &[2.0, 10.0] } else { &[2.0] };
                    for &rate in rates {
                        for push in ["1.5s", "7s", "outage"] {
                            for p1 in [true, false] {
                                jobs.push(make_job(&tapes, ti, spec, mode, mix, rate, push, p1));
                            }
                        }
                    }
                }
            }
        }
    }
    // Outage extras: V1 with a guard-only v2 block, and a large arb budget.
    let guard = Spec {
        name: "V1-deployed+guard".into(),
        v2: V2Mode::GuardOnly {
            max_mark_age: 150,
            observed: 0,
        },
        ..Spec::v1_deployed()
    };
    for ti in 0..tapes.len() {
        for mode in [Mode::A, Mode::B] {
            for p1 in [true, false] {
                jobs.push(make_job(
                    &tapes,
                    ti,
                    &guard,
                    mode,
                    Mix::ALL,
                    2.0,
                    "outage",
                    p1,
                ));
            }
        }
    }
    let rows = exec_jobs(&tapes, &jobs);
    write_csv(&out_dir.join("main_grid.csv"), &rows);
    let mut big = Vec::new();
    for ti in 0..tapes.len() {
        for spec in specs.iter().chain(std::iter::once(&guard)) {
            for mode in [Mode::A, Mode::B] {
                for p1 in [true, false] {
                    let mut j = make_job(&tapes, ti, spec, mode, Mix::ALL, 2.0, "outage", p1);
                    j.sc.arb_budget_usd = 40_000.0;
                    j.spec.name = format!("{}|arb40k", spec.name);
                    big.push(j);
                }
            }
        }
    }
    let big_rows = exec_jobs(&tapes, &big);
    write_csv(&out_dir.join("outage_arb40k.csv"), &big_rows);
    eprintln!(
        "main grid {} + {} runs {:.1}s",
        rows.len(),
        big_rows.len(),
        t3.elapsed().as_secs_f64()
    );

    // Robustness: an arb that SPLITS into max_fill-sized calls within one slot, and the
    // P1 max_mark_age sensitivity (the default 150 slots = 60 s).
    let mut rspecs: Vec<Spec> = vec![Spec::v1_deployed(), guard.clone()];
    let mut g25 = guard.clone();
    g25.name = "V1-deployed+guard25".into();
    g25.v2 = V2Mode::GuardOnly {
        max_mark_age: 25,
        observed: 0,
    };
    rspecs.push(g25);
    rspecs.push(Spec::v2_default());
    rspecs.push(tuned_b.spec("V2-tuned-B"));
    rspecs.push(tuned_a.spec("V2-tuned-A"));
    for age in [25u16, 10] {
        let mut c = tuned_a.clone();
        c.knobs.max_mark_age_slots = age;
        rspecs.push(c.spec(&format!("V2-tuned-A|age{age}")));
    }
    let mut rj = Vec::new();
    for ti in 0..tapes.len() {
        for spec in &rspecs {
            for mode in [Mode::A, Mode::B] {
                for push in ["1.5s", "7s", "outage"] {
                    for budget in [5_000.0, 40_000.0] {
                        let mut j = make_job(&tapes, ti, spec, mode, Mix::ALL, 2.0, push, true);
                        j.sc.arb_split = true;
                        j.sc.arb_budget_usd = budget;
                        j.spec.name = format!("{}|split{}k", spec.name, budget / 1000.0);
                        rj.push(j);
                    }
                }
            }
        }
    }
    let rrows = exec_jobs(&tapes, &rj);
    write_csv(&out_dir.join("robust_split_arb.csv"), &rrows);
    for mode in [Mode::A, Mode::B] {
        for push in ["1.5s", "7s", "outage"] {
            let _ = writeln!(md, "### Robustness — SPLITTING arb (max_fill chunks, same slot), benign+arb+mom, P1, Mode {}, push {push}: LP PnL $ arb $5k / $40k [benign fill ratio]\n\n| tape | {} |\n|---|{}", mode.tag(), rspecs.iter().map(|s| s.name.clone()).collect::<Vec<_>>().join(" | "), "---|".repeat(rspecs.len()));
            for t in &tapes {
                let cells: Vec<String> = rspecs
                    .iter()
                    .map(|s| {
                        let a = find(
                            &rrows,
                            &t.label(),
                            &format!("{}|split5k", s.name),
                            mode,
                            "benign+arb+mom",
                            2.0,
                            push,
                            true,
                        );
                        let b = find(
                            &rrows,
                            &t.label(),
                            &format!("{}|split40k", s.name),
                            mode,
                            "benign+arb+mom",
                            2.0,
                            push,
                            true,
                        );
                        let bl = |r: &Row| {
                            if r.m.min_equity_usd < -params::LP_CAPITAL_USD {
                                "!"
                            } else {
                                ""
                            }
                        };
                        format!(
                            "{:.0}{} / {:.0}{} [{:.2}]",
                            a.m.lp_pnl_usd,
                            bl(a),
                            b.m.lp_pnl_usd,
                            bl(b),
                            b.m.benign_filled_usd / b.m.benign_req_usd.max(1e-9)
                        )
                    })
                    .collect();
                let _ = writeln!(md, "| {} | {} |", t.label(), cells.join(" | "));
            }
            md.push('\n');
        }
    }

    // Limit sensitivity: the UI's actual default slippage is 500 bps (percolator-launch
    // app/lib/slippage.ts DEFAULT_SLIPPAGE_BPS); the coordinator asked for 100 bps.
    let mut lj = Vec::new();
    for ti in 0..tapes.len() {
        for spec in &specs {
            let mut j = make_job(
                &tapes,
                ti,
                spec,
                Mode::A,
                Mix::BENIGN_ARB,
                2.0,
                "1.5s",
                true,
            );
            j.sc.limit_bps = 500.0;
            j.spec.name = format!("{}|limit500", spec.name);
            lj.push(j);
        }
    }
    let lrows = exec_jobs(&tapes, &lj);
    write_csv(&out_dir.join("modeA_limit500.csv"), &lrows);
    {
        let _ = writeln!(md, "### Mode A limit sensitivity (benign+arb, 1.5 s, P1, 2/min): LP PnL $ / benign fill ratio, limit 100 bps vs 500 bps (UI default)\n\n| tape | {} |\n|---|{}", specs.iter().map(|s| s.name.clone()).collect::<Vec<_>>().join(" | "), "---|".repeat(specs.len()));
        for t in &tapes {
            let cells: Vec<String> = specs
                .iter()
                .map(|s| {
                    let a = find(
                        &rows,
                        &t.label(),
                        &s.name,
                        Mode::A,
                        "benign+arb",
                        2.0,
                        "1.5s",
                        true,
                    );
                    let b = find(
                        &lrows,
                        &t.label(),
                        &format!("{}|limit500", s.name),
                        Mode::A,
                        "benign+arb",
                        2.0,
                        "1.5s",
                        true,
                    );
                    let fr = |m: &Metrics| m.benign_filled_usd / m.benign_req_usd.max(1e-9);
                    format!(
                        "{:.0}/{:.2} vs {:.0}/{:.2}",
                        a.m.lp_pnl_usd,
                        fr(&a.m),
                        b.m.lp_pnl_usd,
                        fr(&b.m)
                    )
                })
                .collect();
            let _ = writeln!(md, "| {} | {} |", t.label(), cells.join(" | "));
        }
        md.push('\n');
    }

    // ---- 4. Observed-staleness analysis ----
    let t4 = Instant::now();
    let ns: [u16; 6] = [0, 150, 375, 750, 1500, 3000];
    let mut sj = Vec::new();
    for ti in 0..tapes.len() {
        for &n in &ns {
            let spec = Spec {
                name: format!("V2-default|obs{n}"),
                v2: V2Mode::Default {
                    max_mark_age: None,
                    observed: Some(n),
                },
                ..Spec::v2_default()
            };
            for rate in [2.0, 10.0] {
                for p1 in [false, true] {
                    sj.push(make_job(
                        &tapes,
                        ti,
                        &spec,
                        Mode::B,
                        Mix::BENIGN,
                        rate,
                        "1.5s",
                        p1,
                    ));
                }
            }
            for mode in [Mode::A, Mode::B] {
                sj.push(make_job(
                    &tapes,
                    ti,
                    &spec,
                    mode,
                    Mix::ALL,
                    2.0,
                    "outage",
                    false,
                ));
            }
        }
    }
    let srows = exec_jobs(&tapes, &sj);
    write_csv(&out_dir.join("observed_stale.csv"), &srows);
    eprintln!(
        "staleness {} runs {:.1}s",
        srows.len(),
        t4.elapsed().as_secs_f64()
    );

    // ---- 5. Tables ----
    tables(&mut md, &tapes, &rows, &big_rows, &srows, &ns);
    let sha = std::process::Command::new("git")
        .args([
            "-C",
            root.parent().unwrap().to_str().unwrap(),
            "rev-parse",
            "HEAD",
        ])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let dirty = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!(
            "git -C {} diff HEAD -- src Cargo.toml | shasum -a 256 | cut -c1-16; git -C {} status --short -- src Cargo.toml | tr '\\n' ' '",
            root.parent().unwrap().display(),
            root.parent().unwrap().display()
        ))
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).replace('\n', " ").trim().to_string())
        .unwrap_or_default();
    let _ = writeln!(
        md,
        "\n---\nmatcher git SHA: `{sha}`; uncommitted src diff sha256[..16] + status: `{dirty}`; total runtime {:.1}s; quick={quick}\n",
        t0.elapsed().as_secs_f64()
    );
    std::fs::write(out_dir.join("tables.md"), &md).unwrap();
    eprintln!(
        "done in {:.1}s -> {}",
        t0.elapsed().as_secs_f64(),
        out_dir.display()
    );
}

#[allow(clippy::too_many_arguments)]
fn find<'a>(
    rows: &'a [Row],
    tape: &str,
    spec: &str,
    mode: Mode,
    mix: &str,
    rate: f64,
    push: &str,
    p1: bool,
) -> &'a Row {
    rows.iter()
        .find(|r| {
            r.tape == tape
                && r.spec == spec
                && r.mode == mode
                && r.mix == mix
                && r.rate == rate
                && r.push == push
                && r.p1 == p1
        })
        .unwrap_or_else(|| panic!("missing row {tape} {spec} {mode:?} {mix} {rate} {push} {p1}"))
}

/// `!` = the LP's equity fell below -capital at some minute mark (LP would be wiped out).
fn cell(r: &Row) -> String {
    let blown = if r.m.min_equity_usd < -params::LP_CAPITAL_USD {
        "!"
    } else {
        ""
    };
    format!("{:.0} ({:+.1}){blown}", r.m.lp_pnl_usd, r.m.lp_pnl_bps())
}

#[allow(clippy::too_many_arguments)]
fn tables(md: &mut String, tapes: &[Tape], rows: &[Row], big: &[Row], srows: &[Row], ns: &[u16]) {
    let specs = [
        "V1-deployed",
        "V1-kind1",
        "V2-default",
        "V2-tuned-B",
        "V2-tuned-A",
    ];
    let mixes = ["benign", "arb", "benign+arb", "benign+arb+mom"];
    for (mode, title) in [
        (Mode::A, "Mode A (v18.2 actual: fills settle at the mark)"),
        (
            Mode::B,
            "Mode B (hypothetical: fills settle at the matcher exec price)",
        ),
    ] {
        for push in ["1.5s", "7s", "outage"] {
            let _ = writeln!(
                md,
                "### {title} — push {push}, P1 wrapper, benign 2/min\n\nLP PnL $ (bps of LP volume)\n\n| tape | IS/OOS | mix | {} |\n|---|---|---|{}",
                specs.join(" | "),
                "---|".repeat(specs.len())
            );
            for t in tapes {
                for mix in mixes {
                    let cells: Vec<String> = specs
                        .iter()
                        .map(|s| cell(find(rows, &t.label(), s, mode, mix, 2.0, push, true)))
                        .collect();
                    let _ = writeln!(
                        md,
                        "| {} | {} | {} | {} |",
                        t.label(),
                        if t.in_sample { "IS" } else { "OOS" },
                        mix,
                        cells.join(" | ")
                    );
                }
            }
            md.push('\n');
        }
        // IS vs OOS aggregate (benign+arb, 1.5s, P1).
        let _ = writeln!(
            md,
            "### {title} — in-sample vs out-of-sample aggregate (benign+arb, 1.5 s and 7 s pushes, P1, 2/min)\n\n| params | IS worst $ | IS sum $ | OOS worst $ | OOS sum $ | IS benign cost bps | OOS benign cost bps | OOS benign fill ratio |\n|---|---|---|---|---|---|---|---|"
        );
        for s in specs {
            let sel = |ins: bool| -> Vec<&Row> {
                rows.iter()
                    .filter(|r| {
                        r.spec == s
                            && r.mode == mode
                            && r.mix == "benign+arb"
                            && r.rate == 2.0
                            && (r.push == "1.5s" || r.push == "7s")
                            && r.p1
                            && r.in_sample == ins
                    })
                    .collect()
            };
            let agg = |v: &[&Row]| {
                let w = v
                    .iter()
                    .map(|r| r.m.lp_pnl_usd)
                    .fold(f64::INFINITY, f64::min);
                let sum: f64 = v.iter().map(|r| r.m.lp_pnl_usd).sum();
                let n: f64 = v.iter().map(|r| r.m.benign_filled_usd).sum();
                let c: f64 = v.iter().map(|r| r.m.benign_cost_bps_x_usd).sum();
                let req: f64 = v.iter().map(|r| r.m.benign_req_usd).sum();
                (w, sum, c / n, n / req)
            };
            let (iw, is, ic, _) = agg(&sel(true));
            let (ow, os, oc, ofr) = agg(&sel(false));
            let _ = writeln!(
                md,
                "| {s} | {iw:.0} | {is:.0} | {ow:.0} | {os:.0} | {ic:.1} | {oc:.1} | {ofr:.3} |"
            );
        }
        md.push('\n');
    }

    // Friction / refusals summary, Mode A, benign only, 1.5 s, P1.
    let _ = writeln!(md, "### Benign friction (Mode A, benign 2/min, push 1.5 s, P1): fills / limit-rejects(>100 bps quote) / refusals / zero-fills / benign fill ratio / quoted spread bps\n\n| tape | {} |\n|---|{}", specs.join(" | "), "---|".repeat(specs.len()));
    for t in tapes {
        let cells: Vec<String> = specs
            .iter()
            .map(|s| {
                let r = find(rows, &t.label(), s, Mode::A, "benign", 2.0, "1.5s", true);
                let m = &r.m;
                format!(
                    "{}/{}/{}/{}/{:.2}/{:.0}",
                    m.benign_fills,
                    m.limit_rejects_benign,
                    m.err_total(Some(sim::Actor::Benign)),
                    m.zero_fills,
                    m.benign_filled_usd / m.benign_req_usd.max(1e-9),
                    m.benign_quote_bps()
                )
            })
            .collect();
        let _ = writeln!(md, "| {} | {} |", t.label(), cells.join(" | "));
    }
    md.push('\n');

    // Outage: P1 vs no-P1, all mixes ALL, 2/min, arb 5k and 40k.
    for (label, src, suffix) in [
        ("arb budget $5k", rows, ""),
        ("arb budget $40k", big, "|arb40k"),
    ] {
        for mode in [Mode::A, Mode::B] {
            let sp: Vec<String> = specs
                .iter()
                .map(|s| s.to_string())
                .chain(std::iter::once("V1-deployed+guard".to_string()))
                .collect();
            let _ = writeln!(md, "### OUTAGE (10-min keeper freeze at the largest 10-min move), benign+arb+mom, Mode {}, {label}: LP PnL $ with P1 / without P1\n\n| tape | {} |\n|---|{}", mode.tag(), sp.join(" | "), "---|".repeat(sp.len()));
            for t in tapes {
                let cells: Vec<String> = sp
                    .iter()
                    .map(|s| {
                        let name = format!("{s}{suffix}");
                        let a = find(
                            src,
                            &t.label(),
                            &name,
                            mode,
                            "benign+arb+mom",
                            2.0,
                            "outage",
                            true,
                        );
                        let b = find(
                            src,
                            &t.label(),
                            &name,
                            mode,
                            "benign+arb+mom",
                            2.0,
                            "outage",
                            false,
                        );
                        format!("{:.0} / {:.0}", a.m.lp_pnl_usd, b.m.lp_pnl_usd)
                    })
                    .collect();
                let _ = writeln!(md, "| {} | {} |", t.label(), cells.join(" | "));
            }
            md.push('\n');
        }
    }

    // Observed staleness.
    let _ = writeln!(md, "### observed_stale_slots: benign trades falsely refused (Custom 8002) with a LIVE keeper (1.5 s pushes), V2-default otherwise; % of benign attempts, [2/min | 10/min], no-P1 (P1 identical if equal)\n\n| tape | {} |\n|---|{}", ns.iter().map(|n| format!("N={n}")).collect::<Vec<_>>().join(" | "), "---|".repeat(ns.len()));
    for t in tapes {
        let cells: Vec<String> = ns
            .iter()
            .map(|n| {
                let name = format!("V2-default|obs{n}");
                let f = |rate: f64, p1: bool| {
                    let r = find(
                        srows,
                        &t.label(),
                        &name,
                        Mode::B,
                        "benign",
                        rate,
                        "1.5s",
                        p1,
                    );
                    100.0 * r.m.err_count(Some(sim::Actor::Benign), "Custom(8002)") as f64
                        / r.m.benign_attempts.max(1) as f64
                };
                let (a, b, c, d) = (f(2.0, false), f(10.0, false), f(2.0, true), f(10.0, true));
                if (a - c).abs() < 1e-12 && (b - d).abs() < 1e-12 {
                    format!("{a:.2}% / {b:.2}%")
                } else {
                    format!("{a:.2}% / {b:.2}% (P1: {c:.2}% / {d:.2}%)")
                }
            })
            .collect();
        let _ = writeln!(md, "| {} | {} |", t.label(), cells.join(" | "));
    }
    md.push('\n');
    for mode in [Mode::A, Mode::B] {
        let _ = writeln!(md, "### observed_stale_slots in the OUTAGE (no P1, benign+arb+mom, Mode {}): LP PnL $ and loss avoided vs N=0 (disabled)\n\n| tape | {} |\n|---|{}", mode.tag(), ns.iter().map(|n| format!("N={n}")).collect::<Vec<_>>().join(" | "), "---|".repeat(ns.len()));
        for t in tapes {
            let base = find(
                srows,
                &t.label(),
                "V2-default|obs0",
                mode,
                "benign+arb+mom",
                2.0,
                "outage",
                false,
            )
            .m
            .lp_pnl_usd;
            let cells: Vec<String> = ns
                .iter()
                .map(|n| {
                    let r = find(
                        srows,
                        &t.label(),
                        &format!("V2-default|obs{n}"),
                        mode,
                        "benign+arb+mom",
                        2.0,
                        "outage",
                        false,
                    );
                    format!("{:.0} ({:+.0})", r.m.lp_pnl_usd, r.m.lp_pnl_usd - base)
                })
                .collect();
            let _ = writeln!(md, "| {} | {} |", t.label(), cells.join(" | "));
        }
        md.push('\n');
    }
}
