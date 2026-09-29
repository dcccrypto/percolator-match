# Matcher v2 LP backtest: results

**Matcher code:** `percolator-match` @ `49fb7dc77c0c094533ca75cfa2e040f8a53e675c` (clean tree: no uncommitted changes under `src/` or `Cargo.toml`).
**Reproduce:**

```sh
cargo run --release --manifest-path backtest/Cargo.toml -- all     # full run, ~90 s wall on an M-series Mac (+~30 s first compile)
cargo test --release --manifest-path backtest/Cargo.toml            # 11 unit tests (RNG, accounting identity, zero-edge, monotone quote, ...)
cargo clippy --manifest-path backtest/Cargo.toml --all-targets -- -D warnings
cargo run --release --manifest-path backtest/Cargo.toml -- probe   # reproducer for the kind-2 size-clip finding (section 6)
```

Outputs: `backtest/results/*.csv` (one row per simulation; every error code counted per actor), and `backtest/results/tables.md` (every table the run produces). The tables below were copied from that run. No sub-sampling: all tapes run in full.

## 0. Read this first: two settlement modes

On v18.2 the wrapper settles every fill **at the asset mark**, not at the matcher's `exec_price` (percolator-prog `6377376a` `src/v16_program.rs:11722-11752`, F-TRADENOCPI-FEE). The quoted spread is only used for the taker's limit check. So every row is reported twice:

- **Mode A, "v18.2 actual".** A fill settles at the oracle price handed to the matcher, which is the mark M. The LP earns no spread. The matcher can only protect the LP through fill size (max_fill, inventory cap, the CP-impact size clip, headroom), zero-fills, and stale refusals. Benign and momentum takers send a limit of M·(1 ± 100 bps). A quote outside that limit reverts, is counted as a *limit-reject*, and commits no matcher state. The arb sends no limit.
- **Mode B, "settle-at-exec" (hypothetical).** This needs a wrapper change, for example settling at the matcher price inside the P1 band, or the new negotiated fee-request bits. Here the spread is LP revenue.

**Mode A is what exists today.** Mode B numbers describe a wrapper that does not exist yet.

## 1. Headline

LP capital is $10k. LP PnL is in $ and in bps of LP volume. Scenario: mix benign+arb, benign flow 2/min, P1 wrapper, aggregated over 1.5 s **and** 7 s keeper pushes (worst = worst single tape×push run; sum = sum over runs). **IS** = SOL/JUP calm+volatile (the tuning set). **OOS** = TRUMP, PENGU, BURNIE. Rows marked `!` in the per-tape tables mean LP equity fell below −$10k at some minute (the LP would be wiped out).

| params | Mode A IS worst $ | Mode A OOS worst $ | Mode A OOS sum $ | Mode A OOS benign fill | Mode B IS worst $ | Mode B OOS worst $ | Mode B IS / OOS benign all-in cost bps |
|---|---|---|---|---|---|---|---|
| V1-deployed | -5161 | -70895 | -189147 | 0.502 | 7180 | 7941 | 139.5 / 141.6 |
| V1-kind1 | -5161 | -70895 | -189147 | 0.502 | 7186 | 7951 | 139.6 / 141.8 |
| V2-default | -3380 | -42142 | -105868 | 0.214 | 6926 | 7732 | 135.2 / 147.1 |
| V2-tuned-B | -5637 | -70813 | -183236 | 0.705 | 2109 | 2300 | 58.1 / 74.2 |
| V2-tuned-A | -1055 | -4909 | -9361 | 0.873 | 3320 | 3966 | 73.1 / 80.3 |

What the table says:

1. **Mode A (today):**
   - Every param set loses money to the latency arb. The arb clears ≈ |P−M| − 20 bps (two wrapper fees) per round trip, whatever the quote is.
   - V1-deployed and V1-kind1 give identical Mode A results, because kind 1's impact only moves price, never size.
   - **V2-tuned-A cuts the worst out-of-sample loss by about 14×** (−$4.9k vs −$70.9k for V1-deployed). It does this with no fee lever at all:
     - `max_total = 100` together with skew 300 and CP impact 5000 turn the kind-2 size clip into two things: an inventory cap at about 23% of `max_inventory_abs`, and a **volatility circuit breaker**. When base + adaptive fee + skew ≥ max_total, `quote_adaptive` zero-fills.
     - The price is lost UX: 13% of benign notional goes unfilled out-of-sample (25% on TRUMP's 97%-range day).
   - This holds against an arb that splits into many max_fill-sized calls per slot (section 4).
2. **Mode B (hypothetical):**
   - Absolute $ figures are large because benign flow is fixed at 2 or 10 per minute regardless of LP size ($0.4–2M/day of benign volume against a $10k LP). Compare params with each other, not the dollar levels.
   - V1-deployed "earns" the most only because it charges benign takers about 140 bps all-in (its skew saturates, section 6.4).
   - V2-tuned-B satisfies the ≤ 60 bps cost constraint in-sample (58.1) but **breaks it out-of-sample (74.2)**. Its adaptive fee reacts to memecoin volatility. This is overfitting to the calm/volatile SOL/JUP set.
3. **Under a 100 bps limit, V2-default fills 0% of benign trades on 8 of 10 tapes** (Mode A). Its cold-start quote is base 20 + fee_cold 80 + impact ≥ 101 bps. The trade reverts, so the vol estimator never warms up (section 6.2). At the UI's actual default slippage of 500 bps (`percolator-launch app/lib/slippage.ts`), V2-default fills 97–100% (limit-sensitivity table, section 8).

## 2. Recommended kind-2 defaults

**For v18.2 (Mode A), use V2-tuned-A.** Values as built by the harness for a $10k LP at leverage 10:

| field | value | note |
|---|---|---|
| kind | 2 | |
| trading_fee_bps | 10 | only feeds `validate()` and the insurance slice; kind 2 prices with the adaptive fee |
| base_spread_bps | 20 | |
| max_total_bps | **100** | keeps every quote inside a 100 bps UI limit and arms the zero-fill breaker |
| impact_k_bps | **5000** | half of exact CP |
| liquidity_notional_e6 | 10 × LP capital (e6) | $100k for a $10k LP |
| skew_spread_mult_bps | **300** | bps at \|inv\| = skew_ref_inventory |
| max_inventory_abs | 40% of capital × leverage, in q at the opening price | unchanged from the wizard |
| max_fill_abs | max_inventory_abs / 4 | unchanged from the wizard (a /10 or /40 grid point did not beat /4 under the new flags) |
| V2Config.flags | 1 (`V2_FLAG_STALE_ALLOW_REDUCING`) | crate default |
| fee_lo_bps / fee_hi_bps / fee_cold_bps | **10 / 80 / 10** | fee_hi is capped by max_total − base. fee_cold = fee_lo avoids the cold-start reject deadlock |
| vol_a_milli / vol_b_den | 1000 / **100** | |
| vol_alpha_bps / vol_warmup / vol_move_cap_10bps | 1000 / 8 / 100 | crate defaults |
| vol_ref_slots | 25 | a 4-slot reference was never better |
| thin_rebate_mult_bps | 150 | = skew_mult / 2 |
| skew_cap_bps / rebate_cap_bps | 100 / 50 | what `default_config_for_kind2` derives from max_total 100 |
| max_mark_age_slots | 150 | 25 and 10 changed nothing at 1.5 s pushes; 10 cost about 12 pp of benign fill at 7 s pushes |
| observed_stale_slots | **0 (off)** | section 3 |
| skew_ref_inventory | max_inventory_abs | |

`default_config_for_kind2(10, 20, 100, 300, max_inv)` does **not** produce these values. It gives fee_lo 30 and fee_cold 80, and vol_b_den 200. Getting there means changing `DEFAULT_FEE_LO_BPS` to 10, `DEFAULT_FEE_COLD_BPS` to 10 (or cold = lo) and `DEFAULT_VOL_B_DEN` to 100, plus the wizard core params above.

**For a future settle-at-exec or fee-request wrapper (Mode B), V2-tuned-B:**
- Core: max_total 400, impact_k 0, liquidity 10× capital, skew 100, thin rebate 0.
- Fees: fee_lo 10, fee_hi 100/150/250 (tied: the fee never reached 100 bps in-sample, so fee_hi is not identified by this data; keep 150), fee_cold 80, vol_a 1000, vol_b_den 100, vol_ref 25.
- Other fields as above.
- This choice is constraint-driven and does not generalize out-of-sample (cost 74 bps against the 60 bps target). Treat it as a starting point, not a calibration.

## 3. observed_stale_slots

Recommendation: **N = 0 (disabled)**, which is the crate default since the security-review commit.

- **False refusals with a live keeper** (1.5 s pushes), as a share of benign attempts at 2/min:

  | tape | N=150 | N=375 | N=750 | N=1500 | N=3000 |
  |---|---|---|---|---|---|
  | BURNIE (linear) | 51% | 38% | 25% | 12% | 2.5% |
  | JUP calm | 34% | 17% | 6% | 1.2% | 0% |
  | TRUMP calm | 15% | 4% | 0.6% | 0% | 0% |

  The guard fires because the price the matcher sees does not change. The BURNIE pool has no trades in about 80% of minutes, and the e6 tick is about 7 bps. Calm Binance days also have long flat stretches.
- **The P1 `mark_slot` cannot override this.** `mark_state` evaluates the observed check even when a fresh `mark_slot` is supplied, so the refusal rates are the same with and without P1.
- **Loss avoided in the OUTAGE scenario is negligible or negative.** In Mode A the best case is +$336 (PENGU volatile, N=150), and BURNIE loses $1.7k from false refusals at N=150. In Mode B the guard costs up to −$25k (BURNIE) and −$6.4k (JUP calm). N ≥ 1500 cannot fire inside a 10-minute (1500-slot) outage at all.
- Stale protection belongs to the authoritative P1 `mark_slot`, not to this heuristic.

## 4. Robustness and outage

- **A splitting arb** (repeated max_fill calls within one slot, budget $5k or $40k) destroys V1 and V2-default in Mode A:
  - TRUMP volatile at 1.5 s: V1 −$279k and V2-default −$281k with a $40k budget.
  - V2-tuned-A: −$5.3k.
  - The protection comes from the inventory-dependent zero-fill, which splitting cannot get around.
- **At 7 s pushes, V2-tuned-A still blows up on TRUMP volatile and BURNIE bridge** (−$11k to −$29k). No matcher parameter fixes a mark that lags a 41%-vol token by 7 s while settling at the mark.
- **Outage** (10-minute keeper freeze at each day's largest 10-minute move):
  - The P1 age guard (150 slots = 60 s) barely helps. The arb is in within seconds of the gap opening and before 60 s pass.
  - A V1 context also needs a v2 block for P1 to do anything. `V1-deployed+guard` rows vs `V1-deployed`: P1 is inert on a block-less V1 context.

## 5. Method

- **Pricing code.** Each tape builds a real `percolator_match::vamm::MatcherCtx`: magic/version, lp_pda = [1;32], lp_account_id = 1, the v2 block set via `set_v2_block(&V2Block::fresh(cfg))`, and `validate()` enforced (the run fails loudly if invalid). Every trade calls `execute_leg(&mut ctx, &MatcherCall{..}, &ext, Some(slot), 0)` then `apply_fill`. The harness also replicates `process_call`'s input checks.
  - Calls are priced on a copy of the ctx and committed only if the simulated transaction succeeds. On Err or a limit-reject nothing commits. A successful zero-fill commits, so estimator and observed-tracker state advance.
  - Every `ProgramError` is counted per actor and error string (`errors` column). Across all runs the only error seen was `Custom(8002)` (stale mark).
- **Units.** 1 token = 1,000,000 q. notional_e6 = q·price_e6/1e6 (micro-USD). oracle_price_e6 = round(P·1e6). LP cash is kept exactly in 1e-12 USD (i128).
  - The harness inventory is asserted equal to `ctx.inventory_base` after every fill.
  - PnL = spread revenue + instant markout (M vs P) + inventory revaluation, checked in a unit test.
- **Market.**
  - True price P = the 1 s Binance close.
  - BURNIE is 1 m, run two ways: (a) linear interpolation; (b) a Brownian bridge in log space with per-second vol = trailing 60-minute realized 1-minute vol / √60. The bridge is **synthetic**: the pool is literally flat in no-trade minutes, so it overstates price-change frequency and arb opportunity.
  - Slots are 400 ms. The mark M is the last pushed P, pushed every 1.5 s (measured median) or 7 s. OUTAGE = pushes frozen for 600 s starting at the day's largest |10-minute return|.
  - P1 variant: `CallExt{mark_slot: Some(last push slot), exec_band_bps: Some(500), taker_reducing: <arb exits only>}`. no-P1: `CallExt::default()`.
- **Flow.** Seeded xorshift64*. Common random numbers across param sets and modes.
  - Benign: Poisson 2/min (also 10/min), 50/50 side, lognormal notional (median $150, σ = 1), capped at max_fill.
  - Arb: every slot, if |P−M| exceeds 25 bps it probes the matcher on a ctx copy.
    - Mode A edge = |P−M| − 20 bps.
    - Mode B edge = entry edge vs exec − 10 − (probed exit spread + 10).
    - It trades min(max_fill, $5k/P) when edge > 5 bps and exits through the matcher at the next push.
  - Momentum: $300 every 30 s in the direction of the 5-minute return, never exits.
  - The wrapper fee (10 bps) is a taker cost only.
- **LP accounting.** Cash + inventory marked at P at the end. Also reported: minute-marked max drawdown, max |inventory| $, fills, zero-fills, partial fills, refusals by actor and code, limit rejects, and volume.
- **Search.**
  - Mode B: full product of the specified grid (4·3·3·3·2·5·3 = 3240 configs × 8 runs). Maximises worst in-sample LP PnL (benign+arb, 1.5 s and 7 s pushes, P1) subject to pooled benign all-in cost ≤ 60 bps.
  - Mode A: 252 configs around tuned-B over impact_k × liquidity × skew × max_fill divisor × max_mark_age × (max_total 400 / fee_cold default) vs (max_total 100 / fee_cold = fee_lo). Maximises worst in-sample Mode A PnL subject to benign filled/requested notional ≥ 90%.

## 6. Matcher findings (not fixed; src untouched)

1. **[Bug, low severity] The kind-2 size clip is non-monotone in *requested* size.** `quote_adaptive` budgets impact with `skew_full = skew_net_bps(inv_pre, q.fill, ...)` at the full requested fill. A larger request raises `skew_full`, which shrinks `budget` and so `fill_max`: **asking for more gets you less.** Reproducer (`-- probe`), V2-default ctx at oracle_price_e6 = 1400 (max_inventory_abs 28,571,428,571,428; max_fill_abs 7,142,857,142,857; liquidity 1e11), inventory_base = −14,285,714,285,714, legacy ext, taker buys:

   | req_size | exec_size | exec_price_e6 |
   |---|---|---|
   | 1,750,000,000,000 | 1,714,954,965,000 | 1456 |
   | 7,000,000,000,000 | 1,653,665,275,714 | 1455 |

   Price is monotone in the *filled* size (unit test `quote_monotone_in_size_and_no_panic`, all kinds, 4 price scales, 9 inventories, both ext variants), so there is no LP loss. The cost falls on takers: a max-size request (the usual UI pattern) is under-filled. Fix: evaluate skew at the clipped fill (one refinement pass, or solve the budget with the skew term inside).
2. **[Design hazard] The estimator is starved by reverts.** `vol_update` runs only inside committed calls. If the cold quote (base + fee_cold + impact) exceeds the taker's limit, every call reverts and warmup never finishes. V2-default is 101+ bps against a 100 bps limit, so 0% of benign trades fill on 8/10 tapes. Set fee_cold ≤ fee_lo or keep max_total within the UI slippage. More generally, the vol estimate samples at trade times, not at mark updates.
3. **[Design] The observed-staleness check ignores a fresh P1 `mark_slot`** (section 3). It is harmless now that the default is 0, but a P1 wrapper cannot vouch for a legitimately flat price.
4. **[Config] V1 skew saturates.** In kinds 0/1 `skew_extra = |inventory_q|·mult/10_000` in raw q, capped at 5000. With 1e6 q/token and mult 50 it hits max_total (200 bps) at |inventory| = 200 q (0.0002 token). V1-deployed is therefore a 60 bps / 200 bps two-state quote: any trade that worsens inventory is priced at 200 bps. Under a 100 bps limit, about 50% of benign trades revert on every tape (Mode A friction table). At the UI's 500 bps default they fill but pay 200 bps.
5. **[Precision] The e6 tick is coarse for sub-cent tokens.** At $0.0014 (BURNIE) one e6 unit is about 7 bps. The ceil/floor rounding toward the LP adds up to one tick to every quote, and flat e6 prices drive the observed-staleness false positives.
6. **No panics and no arithmetic errors** in about 36k simulated days, and none with |req_size| up to i128::MAX in the probe test. The only error returned was `Custom(8002)`. P1's `exec_band_bps = 500` is inert for these configs (max_total ≤ 400).

## 7. Caveats

- **Flow is synthetic.** Benign flow is not calibrated to Percolator (no live flow data) and not scaled to LP size. The arb holds one position and exits at the next push (the splitting variant is in section 4). The momentum trader never exits.
- **The mark is idealized.** Mark = pushed Binance price, so the only mark error is push lag. The real keeper reads a DEX pool, so any CEX–DEX basis is not modelled (it would make the arb worse). The BURNIE tape *is* the keeper's pool.
- **Missing mechanics.** No funding, no liquidation or margin mechanics, and no insurance slice (fee_to_insurance 0). LP capital only sizes caps and sets the `!` flag.
- **Outage placement is adversarial by construction.**
- **The sample is small** (10 tapes). The Mode B pick sits on the constraint boundary with near-ties. The Mode A pick is structural (breaker + inventory cap) and holds out-of-sample, but it trades about 10–25% of benign fill for LP safety, and that trade-off is a product decision.
- **Some limits are assumed.** The 100 bps benign limit is the coordinator's assumption; the UI default is 500 bps (limit-sensitivity table, section 8).

## 8. Tables

### Mode A (v18.2 actual: fills settle at the mark) — push 1.5s, P1 wrapper, benign 2/min

LP PnL $ (bps of LP volume)

| tape | IS/OOS | mix | V1-deployed | V1-kind1 | V2-default | V2-tuned-B | V2-tuned-A |
|---|---|---|---|---|---|---|---|
| SOL_calm | IS | benign | 3 (+0.1) | 3 (+0.1) | 0 (+0.0) | 0 (+0.0) | 8 (+0.1) |
| SOL_calm | IS | arb | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) |
| SOL_calm | IS | benign+arb | -6 (-0.2) | -6 (-0.2) | 0 (+0.0) | 0 (+0.0) | -18 (-0.3) |
| SOL_calm | IS | benign+arb+mom | 6 (+0.1) | 6 (+0.1) | 0 (+0.0) | 0 (+0.0) | -28 (-0.2) |
| SOL_volatile | IS | benign | -100 (-2.7) | -100 (-2.7) | 0 (+0.0) | 0 (+0.0) | -103 (-1.6) |
| SOL_volatile | IS | arb | -832 (-20.3) | -832 (-20.3) | -410 (-20.5) | -832 (-20.3) | -60 (-23.1) |
| SOL_volatile | IS | benign+arb | -861 (-11.2) | -861 (-11.2) | -410 (-20.5) | -832 (-20.3) | 37 (+0.6) |
| SOL_volatile | IS | benign+arb+mom | -840 (-8.1) | -840 (-8.1) | -410 (-20.5) | -832 (-20.3) | -216 (-1.5) |
| JUP_calm | IS | benign | -6 (-0.2) | -6 (-0.2) | 0 (+0.0) | 0 (+0.0) | 55 (+0.9) |
| JUP_calm | IS | arb | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) |
| JUP_calm | IS | benign+arb | 14 (+0.4) | 14 (+0.4) | 0 (+0.0) | 0 (+0.0) | 19 (+0.3) |
| JUP_calm | IS | benign+arb+mom | -1 (-0.0) | -1 (-0.0) | 0 (+0.0) | 0 (+0.0) | 70 (+0.6) |
| JUP_volatile | IS | benign | -99 (-2.7) | -99 (-2.7) | 0 (+0.0) | 0 (+0.0) | -542 (-8.2) |
| JUP_volatile | IS | arb | -1708 (-15.7) | -1708 (-15.7) | -1063 (-15.7) | -1708 (-15.7) | -227 (-15.8) |
| JUP_volatile | IS | benign+arb | -1697 (-12.0) | -1697 (-12.0) | -1265 (-13.4) | -5637 (-34.6) | -1055 (-13.9) |
| JUP_volatile | IS | benign+arb+mom | -1774 (-10.5) | -1774 (-10.5) | -1463 (-10.1) | -4166 (-18.3) | -1257 (-8.9) |
| TRUMP_calm | OOS | benign | -17 (-0.5) | -17 (-0.5) | 0 (+0.0) | 0 (+0.0) | -4 (-0.1) |
| TRUMP_calm | OOS | arb | -13 (-12.5) | -13 (-12.5) | -7 (-12.5) | -13 (-12.5) | -3 (-12.5) |
| TRUMP_calm | OOS | benign+arb | -29 (-0.8) | -29 (-0.8) | -7 (-12.5) | -13 (-12.5) | -18 (-0.3) |
| TRUMP_calm | OOS | benign+arb+mom | 11 (+0.2) | 11 (+0.2) | -7 (-12.5) | -13 (-12.5) | 161 (+1.3) |
| TRUMP_volatile | OOS | benign | -334 (-9.5) | -334 (-9.5) | 0 (+0.0) | 0 (+0.0) | 1550 (+27.9) |
| TRUMP_volatile | OOS | arb | -34924 (-23.5)! | -34924 (-23.5)! | -17303 (-22.9)! | -34924 (-23.5)! | -163 (-17.4) |
| TRUMP_volatile | OOS | benign+arb | -34832 (-22.9)! | -34832 (-22.9)! | -17019 (-22.1)! | -32681 (-21.4)! | -269 (-2.9) |
| TRUMP_volatile | OOS | benign+arb+mom | -34817 (-22.5)! | -34817 (-22.5)! | -18747 (-24.0)! | -42142 (-26.8)! | -3558 (-23.5) |
| PENGU_calm | OOS | benign | 7 (+0.2) | 7 (+0.2) | 0 (+0.0) | -35 (-0.5) | -11 (-0.2) |
| PENGU_calm | OOS | arb | -31 (-15.7) | -31 (-15.7) | -18 (-15.7) | -31 (-15.7) | -6 (-15.7) |
| PENGU_calm | OOS | benign+arb | -21 (-0.6) | -21 (-0.6) | -18 (-15.7) | 2 (+0.0) | 71 (+1.1) |
| PENGU_calm | OOS | benign+arb+mom | -33 (-0.5) | -33 (-0.5) | -18 (-15.7) | 137 (+0.9) | 130 (+0.9) |
| PENGU_volatile | OOS | benign | -53 (-1.5) | -53 (-1.5) | 0 (+0.0) | 493 (+6.7) | -114 (-1.7) |
| PENGU_volatile | OOS | arb | -1301 (-17.1) | -1301 (-17.1) | -782 (-17.1) | -1301 (-17.1) | -114 (-17.1) |
| PENGU_volatile | OOS | benign+arb | -1403 (-12.8) | -1403 (-12.8) | -743 (-13.1) | 705 (+4.9) | -277 (-4.0) |
| PENGU_volatile | OOS | benign+arb+mom | -1231 (-8.6) | -1231 (-8.6) | -799 (-10.9) | -1979 (-8.6) | -205 (-1.4) |
| BURNIE_3d-linear | OOS | benign | 106 (+1.0) | 106 (+1.0) | -110 (-1.1) | 349 (+1.7) | 225 (+1.2) |
| BURNIE_3d-linear | OOS | arb | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) |
| BURNIE_3d-linear | OOS | benign+arb | 206 (+1.9) | 206 (+1.9) | -279 (-2.8) | -82 (-0.4) | 176 (+0.9) |
| BURNIE_3d-linear | OOS | benign+arb+mom | -58 (-0.4) | -58 (-0.4) | 3011 (+14.1) | 1888 (+5.3) | 2260 (+7.0) |
| BURNIE_3d-bridge | OOS | benign | 158 (+1.4) | 158 (+1.4) | -207 (-2.5) | -1667 (-8.0) | -489 (-2.7) |
| BURNIE_3d-bridge | OOS | arb | -24276 (-16.0)! | -24276 (-16.0)! | -12980 (-15.9)! | -24276 (-16.0)! | -48 (-17.3) |
| BURNIE_3d-bridge | OOS | benign+arb | -24358 (-15.0)! | -24358 (-15.0)! | -13185 (-15.0)! | -23159 (-13.5)! | -713 (-3.5) |
| BURNIE_3d-bridge | OOS | benign+arb+mom | -24063 (-14.2)! | -24063 (-14.2)! | -11721 (-12.2)! | -21223 (-11.2)! | 2780 (+7.6) |

### Mode A (v18.2 actual: fills settle at the mark) — in-sample vs out-of-sample aggregate (benign+arb, 1.5 s and 7 s pushes, P1, 2/min)

| params | IS worst $ | IS sum $ | OOS worst $ | OOS sum $ | IS benign cost bps | OOS benign cost bps | OOS benign fill ratio |
|---|---|---|---|---|---|---|---|
| V1-deployed | -5161 | -9391 | -70895 | -189147 | 10.0 | 10.0 | 0.502 |
| V1-kind1 | -5161 | -9391 | -70895 | -189147 | 10.0 | 10.0 | 0.502 |
| V2-default | -3380 | -5877 | -42142 | -105868 | 10.0 | 10.0 | 0.214 |
| V2-tuned-B | -5637 | -10316 | -70813 | -183236 | 10.0 | 10.0 | 0.705 |
| V2-tuned-A | -1055 | -1161 | -4909 | -9361 | 10.0 | 10.0 | 0.873 |

### Benign friction (Mode A, benign 2/min, push 1.5 s, P1): fills / limit-rejects(>100 bps quote) / refusals / zero-fills / benign fill ratio / quoted spread bps

| tape | V1-deployed | V1-kind1 | V2-default | V2-tuned-B | V2-tuned-A |
|---|---|---|---|---|---|
| SOL_calm | 1436/1476/0/0/0.49/60 | 1436/1476/0/0/0.49/60 | 0/2912/0/0/0.00/NaN | 0/2912/0/0/0.00/NaN | 2912/0/0/0/0.90/61 |
| SOL_volatile | 1423/1454/0/0/0.49/60 | 1423/1454/0/0/0.49/61 | 0/2877/0/0/0.00/NaN | 0/2877/0/0/0.00/NaN | 2851/0/0/26/0.85/64 |
| JUP_calm | 1458/1398/0/0/0.51/60 | 1458/1398/0/0/0.51/60 | 0/2856/0/0/0.00/NaN | 0/2856/0/0/0.00/NaN | 2856/0/0/0/0.91/61 |
| JUP_volatile | 1443/1512/0/0/0.49/60 | 1443/1512/0/0/0.49/60 | 0/2955/0/0/0.00/NaN | 0/2955/0/0/0.00/NaN | 2953/0/0/2/0.89/68 |
| TRUMP_calm | 1474/1428/0/0/0.50/60 | 1474/1428/0/0/0.50/60 | 0/2902/0/0/0.00/NaN | 0/2902/0/0/0.00/NaN | 2902/0/0/0/0.92/61 |
| TRUMP_volatile | 1398/1437/0/0/0.50/60 | 1398/1437/0/0/0.50/60 | 0/2835/0/0/0.00/NaN | 0/2835/0/0/0.00/NaN | 2553/0/0/282/0.78/77 |
| PENGU_calm | 1463/1462/0/0/0.49/61 | 1463/1462/0/0/0.49/61 | 0/2925/0/0/0.00/NaN | 2909/16/0/0/0.99/39 | 2925/0/0/0/0.95/62 |
| PENGU_volatile | 1464/1443/0/0/0.49/61 | 1464/1443/0/0/0.49/61 | 0/2907/0/0/0.00/NaN | 2880/27/0/0/0.99/47 | 2905/0/0/2/0.90/69 |
| BURNIE_3d-linear | 4352/4298/0/0/0.49/63 | 4352/4298/0/0/0.49/64 | 6873/1777/0/0/0.48/86 | 8480/170/0/0/0.98/54 | 8505/0/0/145/0.89/69 |
| BURNIE_3d-bridge | 4236/4323/0/0/0.51/64 | 4236/4323/0/0/0.51/64 | 6143/2416/0/0/0.39/89 | 8377/182/0/0/0.98/61 | 8324/0/0/235/0.85/75 |

### Mode A limit sensitivity (benign+arb, 1.5 s, P1, 2/min): LP PnL $ / benign fill ratio, limit 100 bps vs 500 bps (UI default)

| tape | V1-deployed | V1-kind1 | V2-default | V2-tuned-B | V2-tuned-A |
|---|---|---|---|---|---|
| SOL_calm | -6/0.50 vs 36/1.00 | -6/0.50 vs 36/1.00 | 0/0.00 vs 35/1.00 | 0/0.00 vs 36/1.00 | -18/0.91 vs -18/0.91 |
| SOL_volatile | -861/0.50 vs -1107/1.00 | -861/0.50 vs -1107/1.00 | -410/0.00 vs -472/0.99 | -832/0.00 vs -1107/1.00 | 37/0.91 vs 37/0.91 |
| JUP_calm | 14/0.49 vs 53/0.98 | 14/0.49 vs 53/0.98 | 0/0.00 vs 50/0.98 | 0/0.00 vs 53/0.98 | 19/0.90 vs 19/0.90 |
| JUP_volatile | -1697/0.48 vs -3512/1.00 | -1697/0.48 vs -3512/1.00 | -1265/0.38 vs -2912/1.00 | -5637/0.80 vs -3512/1.00 | -1055/0.90 vs -1055/0.90 |
| TRUMP_calm | -29/0.51 vs -23/1.00 | -29/0.51 vs -23/1.00 | -7/0.00 vs -27/1.00 | -13/0.00 vs -23/1.00 | -18/0.95 vs -18/0.95 |
| TRUMP_volatile | -34832/0.49 vs -31214/1.00 | -34832/0.49 vs -31214/1.00 | -17019/0.16 vs -13950/1.00 | -32681/0.62 vs -31214/1.00 | -269/0.75 vs -269/0.75 |
| PENGU_calm | -21/0.51 vs 4/1.00 | -21/0.51 vs 4/1.00 | -18/0.00 vs 16/1.00 | 2/0.99 vs 4/1.00 | 71/0.94 vs 71/0.94 |
| PENGU_volatile | -1403/0.50 vs 1096/1.00 | -1403/0.50 vs 1096/1.00 | -743/0.15 vs 1470/0.99 | 705/0.99 vs 1096/1.00 | -277/0.89 vs -277/0.89 |
| BURNIE_3d-linear | 206/0.51 vs 47/0.98 | 206/0.51 vs 47/0.98 | -279/0.45 vs -369/0.97 | -82/0.96 vs 47/0.98 | 176/0.88 vs 176/0.88 |
| BURNIE_3d-bridge | -24358/0.51 vs -22347/1.00 | -24358/0.51 vs -22347/1.00 | -13185/0.30 vs -11038/1.00 | -23159/0.96 vs -22347/1.00 | -713/0.86 vs -713/0.86 |

### Mode A (v18.2 actual: fills settle at the mark) — push 7s, P1 wrapper, benign 2/min

LP PnL $ (bps of LP volume)

| tape | IS/OOS | mix | V1-deployed | V1-kind1 | V2-default | V2-tuned-B | V2-tuned-A |
|---|---|---|---|---|---|---|---|
| SOL_calm | IS | benign | 4 (+0.1) | 4 (+0.1) | 0 (+0.0) | 0 (+0.0) | 10 (+0.1) |
| SOL_calm | IS | arb | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) |
| SOL_calm | IS | benign+arb | 3 (+0.1) | 3 (+0.1) | 0 (+0.0) | 0 (+0.0) | -21 (-0.3) |
| SOL_calm | IS | benign+arb+mom | 5 (+0.1) | 5 (+0.1) | 0 (+0.0) | 0 (+0.0) | -55 (-0.4) |
| SOL_volatile | IS | benign | 15 (+0.4) | 15 (+0.4) | 0 (+0.0) | 0 (+0.0) | 222 (+3.4) |
| SOL_volatile | IS | arb | -1652 (-17.8) | -1652 (-17.8) | -870 (-17.8) | -1652 (-17.8) | -43 (-26.5) |
| SOL_volatile | IS | benign+arb | -1692 (-13.1) | -1692 (-13.1) | -822 (-10.5) | -1468 (-9.8) | 60 (+0.8) |
| SOL_volatile | IS | benign+arb+mom | -1656 (-10.7) | -1656 (-10.7) | -653 (-4.8) | -1631 (-7.5) | -359 (-2.5) |
| JUP_calm | IS | benign | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | -16 (-0.2) |
| JUP_calm | IS | arb | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) |
| JUP_calm | IS | benign+arb | 10 (+0.3) | 10 (+0.3) | 0 (+0.0) | 0 (+0.0) | -48 (-0.8) |
| JUP_calm | IS | benign+arb+mom | -0 (-0.0) | -0 (-0.0) | 0 (+0.0) | 0 (+0.0) | 167 (+1.4) |
| JUP_volatile | IS | benign | 23 (+0.7) | 23 (+0.7) | 0 (+0.0) | 0 (+0.0) | -635 (-10.4) |
| JUP_volatile | IS | arb | -5252 (-15.3) | -5252 (-15.3) | -3256 (-15.3) | -5252 (-15.3) | -610 (-15.0) |
| JUP_volatile | IS | benign+arb | -5161 (-13.6) | -5161 (-13.6) | -3380 (-13.9) | -2380 (-5.9) | -134 (-1.3) |
| JUP_volatile | IS | benign+arb+mom | -5426 (-13.3) | -5426 (-13.3) | -3763 (-12.8) | -8809 (-18.8) | -1639 (-9.5) |
| TRUMP_calm | OOS | benign | 11 (+0.3) | 11 (+0.3) | 0 (+0.0) | 0 (+0.0) | -37 (-0.6) |
| TRUMP_calm | OOS | arb | -97 (-19.3) | -97 (-19.3) | -55 (-19.4) | -97 (-19.3) | -20 (-19.4) |
| TRUMP_calm | OOS | benign+arb | -104 (-2.5) | -104 (-2.5) | -55 (-19.4) | -97 (-19.3) | 16 (+0.2) |
| TRUMP_calm | OOS | benign+arb+mom | -106 (-1.7) | -106 (-1.7) | -55 (-19.4) | -97 (-19.3) | 197 (+1.6) |
| TRUMP_volatile | OOS | benign | -112 (-3.0) | -112 (-3.0) | 0 (+0.0) | 0 (+0.0) | 69 (+1.2) |
| TRUMP_volatile | OOS | arb | -46469 (-19.4)! | -46469 (-19.4)! | -25371 (-19.0)! | -46469 (-19.4)! | -165 (-15.1) |
| TRUMP_volatile | OOS | benign+arb | -46259 (-19.0)! | -46259 (-19.0)! | -25817 (-19.1)! | -44667 (-18.2)! | -1903 (-10.8) |
| TRUMP_volatile | OOS | benign+arb+mom | -46338 (-18.8)! | -46338 (-18.8)! | -26797 (-19.6)! | -52373 (-20.8)! | -4626 (-19.7) |
| PENGU_calm | OOS | benign | 26 (+0.7) | 26 (+0.7) | 0 (+0.0) | -19 (-0.3) | 86 (+1.3) |
| PENGU_calm | OOS | arb | -73 (-24.2) | -73 (-24.2) | -41 (-24.2) | -73 (-24.2) | -15 (-24.2) |
| PENGU_calm | OOS | benign+arb | -107 (-2.7) | -107 (-2.7) | -41 (-24.2) | -53 (-0.7) | -36 (-0.5) |
| PENGU_calm | OOS | benign+arb+mom | -71 (-1.0) | -71 (-1.0) | -41 (-24.2) | 204 (+1.3) | 224 (+1.6) |
| PENGU_volatile | OOS | benign | -15 (-0.4) | -15 (-0.4) | 0 (+0.0) | 1148 (+16.0) | -278 (-4.4) |
| PENGU_volatile | OOS | arb | -7351 (-16.7) | -7351 (-16.7) | -4484 (-16.7) | -7351 (-16.7) | -99 (-16.4) |
| PENGU_volatile | OOS | benign+arb | -7363 (-15.5) | -7363 (-15.5) | -4654 (-15.6) | -8340 (-16.4) | -1198 (-10.9) |
| PENGU_volatile | OOS | benign+arb+mom | -7293 (-14.5) | -7293 (-14.5) | -4663 (-13.5) | -8383 (-14.3) | -1081 (-6.0) |
| BURNIE_3d-linear | OOS | benign | 77 (+0.7) | 77 (+0.7) | -245 (-2.4) | -1144 (-5.4) | -44 (-0.2) |
| BURNIE_3d-linear | OOS | arb | -3889 (-24.5) | -3889 (-24.5) | -1881 (-24.5) | -3889 (-24.5) | -92 (-39.4) |
| BURNIE_3d-linear | OOS | benign+arb | -3981 (-15.0) | -3981 (-15.0) | -1907 (-24.4) | -4037 (-23.5) | -301 (-1.5) |
| BURNIE_3d-linear | OOS | benign+arb+mom | -3917 (-12.8) | -3917 (-12.8) | -1850 (-24.5) | -4802 (-26.6) | 2171 (+6.7) |
| BURNIE_3d-bridge | OOS | benign | -415 (-4.0) | -415 (-4.0) | -143 (-1.7) | -730 (-3.6) | 61 (+0.3) |
| BURNIE_3d-bridge | OOS | arb | -71045 (-14.5)! | -71045 (-14.5)! | -41569 (-14.4)! | -71045 (-14.5)! | -105 (-15.8) |
| BURNIE_3d-bridge | OOS | benign+arb | -70895 (-14.2)! | -70895 (-14.2)! | -42142 (-14.2)! | -70813 (-13.9)! | -4909 (-10.4) |
| BURNIE_3d-bridge | OOS | benign+arb+mom | -70455 (-13.9)! | -70455 (-13.9)! | -40007 (-13.0)! | -69813 (-13.2)! | -1444 (-2.2) |

### Mode A (v18.2 actual: fills settle at the mark) — push outage, P1 wrapper, benign 2/min

LP PnL $ (bps of LP volume)

| tape | IS/OOS | mix | V1-deployed | V1-kind1 | V2-default | V2-tuned-B | V2-tuned-A |
|---|---|---|---|---|---|---|---|
| SOL_calm | IS | benign | 3 (+0.1) | 3 (+0.1) | 0 (+0.0) | 0 (+0.0) | 1 (+0.0) |
| SOL_calm | IS | arb | -15 (-14.6) | -15 (-14.6) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) |
| SOL_calm | IS | benign+arb | -9 (-0.3) | -9 (-0.3) | 0 (+0.0) | 0 (+0.0) | -23 (-0.3) |
| SOL_calm | IS | benign+arb+mom | -12 (-0.2) | -12 (-0.2) | 0 (+0.0) | 0 (+0.0) | -13 (-0.1) |
| SOL_volatile | IS | benign | -18 (-0.5) | -18 (-0.5) | 0 (+0.0) | 0 (+0.0) | 40 (+0.6) |
| SOL_volatile | IS | arb | 192 (+10.7) | 192 (+10.7) | 122 (+12.7) | 192 (+10.7) | 69 (+34.1) |
| SOL_volatile | IS | benign+arb | 55 (+1.0) | 55 (+1.0) | 95 (+10.5) | 62 (+3.4) | 93 (+1.4) |
| SOL_volatile | IS | benign+arb+mom | -50 (-0.6) | -50 (-0.6) | 122 (+12.7) | -31 (-1.7) | 62 (+0.4) |
| JUP_calm | IS | benign | 19 (+0.5) | 19 (+0.5) | 0 (+0.0) | 0 (+0.0) | -24 (-0.4) |
| JUP_calm | IS | arb | -54 (-53.5) | -54 (-53.5) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) |
| JUP_calm | IS | benign+arb | -46 (-1.3) | -46 (-1.3) | 0 (+0.0) | 0 (+0.0) | -40 (-0.6) |
| JUP_calm | IS | benign+arb+mom | -44 (-0.8) | -44 (-0.8) | 0 (+0.0) | 0 (+0.0) | 176 (+1.4) |
| JUP_volatile | IS | benign | -45 (-1.2) | -45 (-1.2) | 0 (+0.0) | 0 (+0.0) | -387 (-6.0) |
| JUP_volatile | IS | arb | -1844 (-17.7) | -1844 (-17.7) | -1146 (-17.7) | -1844 (-17.7) | -240 (-17.6) |
| JUP_volatile | IS | benign+arb | -1784 (-12.8) | -1784 (-12.8) | -1371 (-16.5) | 13 (+0.1) | -740 (-9.5) |
| JUP_volatile | IS | benign+arb+mom | -1691 (-10.2) | -1691 (-10.2) | -1574 (-12.7) | -4039 (-18.8) | -1156 (-8.0) |
| TRUMP_calm | OOS | benign | -5 (-0.1) | -5 (-0.1) | 0 (+0.0) | 0 (+0.0) | 29 (+0.5) |
| TRUMP_calm | OOS | arb | -28 (-28.2) | -28 (-28.2) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) |
| TRUMP_calm | OOS | benign+arb | -15 (-0.4) | -15 (-0.4) | 0 (+0.0) | 0 (+0.0) | -34 (-0.5) |
| TRUMP_calm | OOS | benign+arb+mom | -44 (-0.8) | -44 (-0.8) | 0 (+0.0) | 0 (+0.0) | 170 (+1.4) |
| TRUMP_volatile | OOS | benign | -268 (-8.0) | -268 (-8.0) | 0 (+0.0) | 0 (+0.0) | 1015 (+19.3) |
| TRUMP_volatile | OOS | arb | -24084 (-19.0)! | -24084 (-19.0)! | -12540 (-19.0)! | -24084 (-19.0)! | -161 (-17.1) |
| TRUMP_volatile | OOS | benign+arb | -24492 (-18.8)! | -24492 (-18.8)! | -12645 (-18.9)! | -22987 (-17.6)! | -793 (-8.2) |
| TRUMP_volatile | OOS | benign+arb+mom | -25052 (-18.9)! | -25052 (-18.9)! | -13824 (-20.3)! | -29748 (-22.0)! | -3321 (-21.7) |
| PENGU_calm | OOS | benign | -13 (-0.3) | -13 (-0.3) | 0 (+0.0) | -58 (-0.8) | -14 (-0.2) |
| PENGU_calm | OOS | arb | -74 (-37.2) | -74 (-37.2) | -42 (-37.2) | -74 (-37.2) | -15 (-37.2) |
| PENGU_calm | OOS | benign+arb | -64 (-1.8) | -64 (-1.8) | -42 (-36.9) | 84 (+1.2) | 80 (+1.2) |
| PENGU_calm | OOS | benign+arb+mom | -50 (-0.7) | -50 (-0.7) | -42 (-36.9) | 212 (+1.3) | 212 (+1.4) |
| PENGU_volatile | OOS | benign | 59 (+1.8) | 59 (+1.8) | 0 (+0.0) | 2879 (+43.1) | 260 (+4.3) |
| PENGU_volatile | OOS | arb | -1452 (-19.6) | -1452 (-19.6) | -751 (-17.1) | -1249 (-17.1) | -109 (-17.0) |
| PENGU_volatile | OOS | benign+arb | -1476 (-13.4) | -1476 (-13.4) | -674 (-12.1) | -3803 (-26.6) | 243 (+3.3) |
| PENGU_volatile | OOS | benign+arb+mom | -1297 (-9.4) | -1297 (-9.4) | -830 (-11.9) | -774 (-3.5) | -184 (-1.3) |
| BURNIE_3d-linear | OOS | benign | -161 (-1.5) | -161 (-1.5) | 325 (+3.2) | 1072 (+5.2) | 685 (+3.6) |
| BURNIE_3d-linear | OOS | arb | 512 (+541.8) | 512 (+541.8) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) |
| BURNIE_3d-linear | OOS | benign+arb | 454 (+4.1) | 454 (+4.1) | -311 (-5.0) | -120 (-0.8) | -120 (-0.6) |
| BURNIE_3d-linear | OOS | benign+arb+mom | -177 (-1.2) | -177 (-1.2) | 2160 (+15.9) | 4143 (+17.9) | 2680 (+8.3) |
| BURNIE_3d-bridge | OOS | benign | 161 (+1.5) | 161 (+1.5) | -222 (-2.6) | 790 (+3.8) | -392 (-2.2) |
| BURNIE_3d-bridge | OOS | arb | -22980 (-16.2)! | -22980 (-16.2)! | -12399 (-16.0)! | -22980 (-16.2)! | -48 (-17.3) |
| BURNIE_3d-bridge | OOS | benign+arb | -22603 (-14.8)! | -22603 (-14.8)! | -12697 (-15.2)! | -26332 (-16.1)! | -615 (-3.0) |
| BURNIE_3d-bridge | OOS | benign+arb+mom | -22280 (-14.0)! | -22280 (-14.0)! | -10557 (-11.4)! | -17519 (-9.7)! | 3236 (+8.8) |

### Mode B (hypothetical: fills settle at the matcher exec price) — push 1.5s, P1 wrapper, benign 2/min

LP PnL $ (bps of LP volume)

| tape | IS/OOS | mix | V1-deployed | V1-kind1 | V2-default | V2-tuned-B | V2-tuned-A |
|---|---|---|---|---|---|---|---|
| SOL_calm | IS | benign | 9741 (+132.4) | 9752 (+132.5) | 9388 (+128.5) | 3776 (+51.5) | 4033 (+61.1) |
| SOL_calm | IS | arb | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) |
| SOL_calm | IS | benign+arb | 9688 (+131.4) | 9699 (+131.5) | 9168 (+124.3) | 3421 (+46.3) | 4091 (+60.9) |
| SOL_calm | IS | benign+arb+mom | 18465 (+129.0) | 18483 (+129.2) | 15615 (+109.6) | 6777 (+47.4) | 7147 (+56.8) |
| SOL_volatile | IS | benign | 10155 (+133.4) | 10168 (+133.6) | 10546 (+141.5) | 4878 (+64.3) | 4042 (+62.9) |
| SOL_volatile | IS | arb | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) |
| SOL_volatile | IS | benign+arb | 8901 (+123.0) | 8918 (+123.3) | 8895 (+124.0) | 2796 (+38.6) | 4225 (+64.1) |
| SOL_volatile | IS | benign+arb+mom | 21367 (+137.2) | 21376 (+137.2) | 18786 (+121.1) | 10848 (+69.9) | 8335 (+59.1) |
| JUP_calm | IS | benign | 9482 (+133.4) | 9489 (+133.5) | 9104 (+128.5) | 3981 (+56.1) | 4017 (+62.3) |
| JUP_calm | IS | arb | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) |
| JUP_calm | IS | benign+arb | 9065 (+131.6) | 9071 (+131.7) | 8538 (+124.0) | 3608 (+52.5) | 3883 (+61.1) |
| JUP_calm | IS | benign+arb+mom | 17803 (+131.0) | 17812 (+131.0) | 14655 (+108.2) | 6592 (+48.6) | 7139 (+58.5) |
| JUP_volatile | IS | benign | 6647 (+89.5) | 6658 (+89.7) | 7251 (+97.9) | 1807 (+24.4) | 3927 (+59.6) |
| JUP_volatile | IS | arb | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) |
| JUP_volatile | IS | benign+arb | 7180 (+105.7) | 7186 (+105.8) | 6926 (+102.3) | 2109 (+31.1) | 3320 (+54.5) |
| JUP_volatile | IS | benign+arb+mom | 9954 (+71.0) | 9964 (+71.1) | 9077 (+65.0) | 2911 (+20.8) | 7365 (+57.1) |
| TRUMP_calm | OOS | benign | 9301 (+127.7) | 9312 (+127.8) | 9074 (+125.0) | 3004 (+41.2) | 4096 (+61.2) |
| TRUMP_calm | OOS | arb | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) |
| TRUMP_calm | OOS | benign+arb | 9220 (+127.3) | 9231 (+127.4) | 8271 (+115.1) | 2791 (+38.7) | 4182 (+61.3) |
| TRUMP_calm | OOS | benign+arb+mom | 18436 (+132.8) | 18447 (+132.9) | 15814 (+114.8) | 7784 (+56.4) | 7667 (+60.5) |
| TRUMP_volatile | OOS | benign | 12883 (+181.3) | 12894 (+181.4) | 14160 (+200.2) | 8835 (+124.5) | 5814 (+104.8) |
| TRUMP_volatile | OOS | arb | -1726 (-35.3) | -1604 (-38.2) | 0 (+0.0) | -540 (-27.2) | -203 (-42.3) |
| TRUMP_volatile | OOS | benign+arb | 11506 (+118.6) | 11492 (+122.2) | 13362 (+195.9) | 8669 (+106.4) | 4563 (+87.3) |
| TRUMP_volatile | OOS | benign+arb+mom | 7776 (+48.6)! | 7820 (+49.2)! | 9064 (+60.1)! | 2219 (+14.4)! | 5454 (+48.3) |
| PENGU_calm | OOS | benign | 9063 (+130.1) | 9069 (+130.2) | 8054 (+115.5) | 2745 (+39.3) | 4091 (+61.7) |
| PENGU_calm | OOS | arb | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) |
| PENGU_calm | OOS | benign+arb | 9203 (+133.4) | 9211 (+133.5) | 8445 (+121.9) | 3158 (+45.5) | 4064 (+62.6) |
| PENGU_calm | OOS | benign+arb+mom | 20085 (+133.9) | 20092 (+134.0) | 17150 (+114.3) | 9487 (+63.0) | 8407 (+60.0) |
| PENGU_volatile | OOS | benign | 10376 (+141.5) | 10388 (+141.7) | 10108 (+138.3) | 4564 (+62.0) | 4487 (+67.6) |
| PENGU_volatile | OOS | arb | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) |
| PENGU_volatile | OOS | benign+arb | 11174 (+166.6) | 11184 (+166.8) | 11121 (+166.1) | 6150 (+91.3) | 3966 (+65.8) |
| PENGU_volatile | OOS | benign+arb+mom | 21720 (+136.7) | 21732 (+136.8) | 20209 (+127.9) | 11613 (+73.1) | 9347 (+66.5) |
| BURNIE_3d-linear | OOS | benign | 27387 (+130.5) | 27414 (+130.6) | 28540 (+136.6) | 13751 (+65.6) | 13167 (+70.6) |
| BURNIE_3d-linear | OOS | arb | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) |
| BURNIE_3d-linear | OOS | benign+arb | 28557 (+133.2) | 28589 (+133.4) | 29502 (+138.3) | 15390 (+72.0) | 13763 (+71.4) |
| BURNIE_3d-linear | OOS | benign+arb+mom | 52471 (+142.3) | 52506 (+142.3) | 49037 (+133.2) | 27447 (+74.4) | 24551 (+75.6) |
| BURNIE_3d-bridge | OOS | benign | 27951 (+132.2) | 27969 (+132.3) | 28028 (+132.7) | 16529 (+77.9) | 13250 (+72.8) |
| BURNIE_3d-bridge | OOS | arb | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) |
| BURNIE_3d-bridge | OOS | benign+arb | 29117 (+141.0) | 29137 (+141.1) | 30622 (+148.0) | 18435 (+89.0) | 13212 (+73.1) |
| BURNIE_3d-bridge | OOS | benign+arb+mom | 58018 (+145.7) | 58065 (+145.8) | 56935 (+143.3) | 37507 (+93.9) | 28915 (+83.2) |

### Mode B (hypothetical: fills settle at the matcher exec price) — in-sample vs out-of-sample aggregate (benign+arb, 1.5 s and 7 s pushes, P1, 2/min)

| params | IS worst $ | IS sum $ | OOS worst $ | OOS sum $ | IS benign cost bps | OOS benign cost bps | OOS benign fill ratio |
|---|---|---|---|---|---|---|---|
| V1-deployed | 7180 | 76177 | 7941 | 191774 | 139.5 | 141.6 | 0.994 |
| V1-kind1 | 7186 | 76250 | 7951 | 191987 | 139.6 | 141.8 | 0.994 |
| V2-default | 6926 | 73546 | 7732 | 200157 | 135.2 | 147.1 | 0.991 |
| V2-tuned-B | 2109 | 30150 | 2300 | 98736 | 58.1 | 74.2 | 0.995 |
| V2-tuned-A | 3320 | 32310 | 3966 | 85893 | 73.1 | 80.3 | 0.874 |

### Mode B (hypothetical: fills settle at the matcher exec price) — push 7s, P1 wrapper, benign 2/min

LP PnL $ (bps of LP volume)

| tape | IS/OOS | mix | V1-deployed | V1-kind1 | V2-default | V2-tuned-B | V2-tuned-A |
|---|---|---|---|---|---|---|---|
| SOL_calm | IS | benign | 9916 (+132.8) | 9923 (+132.9) | 9381 (+125.8) | 3559 (+47.4) | 4244 (+60.8) |
| SOL_calm | IS | arb | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) |
| SOL_calm | IS | benign+arb | 9087 (+127.8) | 9095 (+127.9) | 8332 (+117.2) | 2616 (+36.7) | 3899 (+59.0) |
| SOL_calm | IS | benign+arb+mom | 18910 (+130.6) | 18919 (+130.7) | 15670 (+108.4) | 7416 (+51.3) | 7313 (+57.2) |
| SOL_volatile | IS | benign | 9255 (+129.6) | 9263 (+129.7) | 8787 (+123.0) | 3135 (+43.9) | 4339 (+66.8) |
| SOL_volatile | IS | arb | -38 (-37.9) | -33 (-32.9) | 0 (+0.0) | 0 (+0.0) | -3 (-14.8) |
| SOL_volatile | IS | benign+arb | 9215 (+128.3) | 9224 (+128.4) | 9085 (+127.4) | 3187 (+43.9) | 4259 (+65.3) |
| SOL_volatile | IS | benign+arb+mom | 21622 (+137.0) | 21629 (+137.0) | 19304 (+122.6) | 11339 (+72.1) | 8296 (+58.8) |
| JUP_calm | IS | benign | 9044 (+131.3) | 9053 (+131.5) | 8767 (+127.3) | 3787 (+54.8) | 3877 (+61.3) |
| JUP_calm | IS | arb | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) |
| JUP_calm | IS | benign+arb | 8746 (+125.9) | 8754 (+126.1) | 8046 (+116.4) | 2559 (+37.0) | 3897 (+60.7) |
| JUP_calm | IS | benign+arb+mom | 17330 (+131.6) | 17338 (+131.6) | 13818 (+105.2) | 5797 (+44.1) | 7192 (+58.9) |
| JUP_volatile | IS | benign | 5883 (+88.2) | 5888 (+88.2) | 5671 (+85.7) | 1044 (+15.7) | 3469 (+56.7) |
| JUP_volatile | IS | arb | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) |
| JUP_volatile | IS | benign+arb | 14294 (+205.5) | 14303 (+205.6) | 14557 (+210.1) | 9855 (+141.1) | 4736 (+76.1) |
| JUP_volatile | IS | benign+arb+mom | 10869 (+75.3) | 10881 (+75.4) | 10226 (+71.1) | 3078 (+21.4) | 7513 (+57.6) |
| TRUMP_calm | OOS | benign | 8506 (+127.0) | 8514 (+127.2) | 7562 (+112.9) | 2537 (+37.9) | 3787 (+60.3) |
| TRUMP_calm | OOS | arb | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) |
| TRUMP_calm | OOS | benign+arb | 9396 (+130.6) | 9404 (+130.7) | 8584 (+119.2) | 3140 (+43.4) | 4207 (+61.8) |
| TRUMP_calm | OOS | benign+arb+mom | 17928 (+130.9) | 17939 (+130.9) | 15778 (+115.9) | 8596 (+63.0) | 7586 (+59.9) |
| TRUMP_volatile | OOS | benign | 7553 (+108.3) | 7560 (+108.4) | 8278 (+118.2) | 3439 (+49.1) | 4284 (+77.7) |
| TRUMP_volatile | OOS | arb | -3514 (-43.9) | -3193 (-47.6) | 0 (+0.0) | 81 (+7.3) | -135 (-59.3) |
| TRUMP_volatile | OOS | benign+arb | 9536 (+109.4) | 9584 (+111.2) | 11525 (+165.1) | 6662 (+84.7) | 4153 (+76.7) |
| TRUMP_volatile | OOS | benign+arb+mom | 11221 (+67.2)! | 11266 (+67.9)! | 13301 (+87.4)! | 7632 (+48.6)! | 6145 (+53.3) |
| PENGU_calm | OOS | benign | 9283 (+131.5) | 9289 (+131.6) | 8958 (+127.1) | 3656 (+51.6) | 4136 (+63.7) |
| PENGU_calm | OOS | arb | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) |
| PENGU_calm | OOS | benign+arb | 9985 (+132.1) | 9992 (+132.2) | 10044 (+133.1) | 4008 (+53.2) | 4227 (+61.7) |
| PENGU_calm | OOS | benign+arb+mom | 20545 (+132.7) | 20555 (+132.8) | 17199 (+111.1) | 7617 (+49.0) | 8780 (+60.9) |
| PENGU_volatile | OOS | benign | 10877 (+150.6) | 10887 (+150.8) | 10932 (+151.3) | 5469 (+75.7) | 4086 (+64.2) |
| PENGU_volatile | OOS | arb | -18 (-17.9) | -14 (-14.4) | 0 (+0.0) | 0 (+0.0) | 1 (+5.8) |
| PENGU_volatile | OOS | benign+arb | 7941 (+113.7) | 7951 (+113.8) | 7732 (+110.9) | 2300 (+32.4) | 3966 (+61.8) |
| PENGU_volatile | OOS | benign+arb+mom | 19526 (+127.5) | 19536 (+127.5) | 18281 (+119.3) | 9936 (+64.5) | 8806 (+64.9) |
| BURNIE_3d-linear | OOS | benign | 27150 (+125.4) | 27185 (+125.5) | 28293 (+131.1) | 11878 (+54.8) | 13335 (+69.4) |
| BURNIE_3d-linear | OOS | arb | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) |
| BURNIE_3d-linear | OOS | benign+arb | 27839 (+128.6) | 27877 (+128.8) | 29916 (+138.8) | 13242 (+61.3) | 13381 (+70.0) |
| BURNIE_3d-linear | OOS | benign+arb+mom | 48871 (+136.5) | 48899 (+136.5) | 45069 (+125.9) | 25078 (+69.9) | 23817 (+75.7) |
| BURNIE_3d-bridge | OOS | benign | 27771 (+134.5) | 27799 (+134.7) | 29973 (+145.7) | 16578 (+80.0) | 13439 (+75.6) |
| BURNIE_3d-bridge | OOS | arb | -92 (-30.3) | -69 (-34.4) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) |
| BURNIE_3d-bridge | OOS | benign+arb | 28299 (+137.4) | 28336 (+137.6) | 31032 (+152.4) | 14790 (+71.8) | 12208 (+70.8) |
| BURNIE_3d-bridge | OOS | benign+arb+mom | 56065 (+140.1) | 56109 (+140.2) | 54736 (+136.7) | 32369 (+80.7) | 28721 (+82.7) |

### Mode B (hypothetical: fills settle at the matcher exec price) — push outage, P1 wrapper, benign 2/min

LP PnL $ (bps of LP volume)

| tape | IS/OOS | mix | V1-deployed | V1-kind1 | V2-default | V2-tuned-B | V2-tuned-A |
|---|---|---|---|---|---|---|---|
| SOL_calm | IS | benign | 9470 (+128.4) | 9479 (+128.6) | 8581 (+117.6) | 2953 (+40.4) | 4102 (+59.7) |
| SOL_calm | IS | arb | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) |
| SOL_calm | IS | benign+arb | 9116 (+126.4) | 9128 (+126.6) | 8491 (+118.8) | 2757 (+38.4) | 3960 (+59.7) |
| SOL_calm | IS | benign+arb+mom | 18312 (+131.2) | 18321 (+131.2) | 15518 (+111.5) | 7842 (+56.3) | 7039 (+57.1) |
| SOL_volatile | IS | benign | 9829 (+137.0) | 9840 (+137.1) | 9696 (+136.1) | 3888 (+54.4) | 3977 (+64.0) |
| SOL_volatile | IS | arb | -527 (-550.7) | -523 (-546.2) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) |
| SOL_volatile | IS | benign+arb | 8908 (+123.3) | 8919 (+123.5) | 9362 (+131.3) | 3800 (+53.2) | 4217 (+65.8) |
| SOL_volatile | IS | benign+arb+mom | 20607 (+133.4) | 20619 (+133.5) | 18283 (+119.2) | 10417 (+67.7) | 8281 (+60.0) |
| JUP_calm | IS | benign | 9358 (+131.9) | 9367 (+132.0) | 8828 (+124.8) | 4048 (+56.9) | 4020 (+61.5) |
| JUP_calm | IS | arb | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) |
| JUP_calm | IS | benign+arb | 8964 (+127.2) | 8975 (+127.4) | 8321 (+119.0) | 2564 (+36.6) | 3848 (+59.8) |
| JUP_calm | IS | benign+arb+mom | 17662 (+131.5) | 17673 (+131.6) | 14601 (+110.3) | 6878 (+51.8) | 7321 (+59.5) |
| JUP_volatile | IS | benign | 6709 (+90.0) | 6721 (+90.1) | 6792 (+91.6) | 1035 (+13.9) | 4037 (+62.2) |
| JUP_volatile | IS | arb | -179 (-180.2) | -174 (-175.7) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) |
| JUP_volatile | IS | benign+arb | 8957 (+125.3) | 8974 (+125.5) | 9174 (+130.4) | 3377 (+47.9) | 3866 (+60.0) |
| JUP_volatile | IS | benign+arb+mom | 11887 (+81.0) | 11900 (+81.1) | 11052 (+76.2) | 4095 (+28.0) | 7761 (+58.3) |
| TRUMP_calm | OOS | benign | 8928 (+127.7) | 8940 (+127.9) | 8390 (+121.7) | 2708 (+39.2) | 3999 (+62.4) |
| TRUMP_calm | OOS | arb | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) |
| TRUMP_calm | OOS | benign+arb | 9309 (+128.8) | 9319 (+128.9) | 8602 (+120.2) | 2922 (+40.6) | 3979 (+61.2) |
| TRUMP_calm | OOS | benign+arb+mom | 17801 (+132.7) | 17808 (+132.8) | 15357 (+115.4) | 8329 (+62.6) | 7482 (+60.4) |
| TRUMP_volatile | OOS | benign | 11724 (+166.2) | 11734 (+166.4) | 15056 (+216.0) | 9624 (+136.3) | 4998 (+95.1) |
| TRUMP_volatile | OOS | arb | -1521 (-138.6) | -1449 (-208.6) | 0 (+0.0) | -1231 (-313.8) | -297 (-224.0) |
| TRUMP_volatile | OOS | benign+arb | 12025 (+167.7) | 12054 (+170.5) | 13163 (+194.2) | 7783 (+106.1) | 4173 (+77.9) |
| TRUMP_volatile | OOS | benign+arb+mom | 10356 (+66.8)! | 10381 (+67.4)! | 10280 (+67.7)! | 2582 (+16.6)! | 5984 (+52.0) |
| PENGU_calm | OOS | benign | 9589 (+130.9) | 9599 (+131.0) | 9318 (+127.9) | 3292 (+44.8) | 4222 (+62.5) |
| PENGU_calm | OOS | arb | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) |
| PENGU_calm | OOS | benign+arb | 9316 (+133.1) | 9322 (+133.2) | 8736 (+126.0) | 3700 (+53.1) | 4073 (+62.7) |
| PENGU_calm | OOS | benign+arb+mom | 20879 (+131.5) | 20884 (+131.5) | 17207 (+109.6) | 7587 (+48.0) | 8965 (+61.3) |
| PENGU_volatile | OOS | benign | 14328 (+208.6) | 14340 (+208.7) | 14376 (+210.6) | 9780 (+141.9) | 4489 (+74.1) |
| PENGU_volatile | OOS | arb | -139 (-138.8) | -135 (-134.3) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) |
| PENGU_volatile | OOS | benign+arb | 4032 (+54.2) | 4042 (+54.3) | 5695 (+78.7) | 54 (+0.7) | 4839 (+74.5) |
| PENGU_volatile | OOS | benign+arb+mom | 23844 (+150.7) | 23853 (+150.8) | 20917 (+133.9) | 13316 (+85.2) | 9249 (+66.0) |
| BURNIE_3d-linear | OOS | benign | 28194 (+132.6) | 28236 (+132.8) | 28777 (+136.7) | 12873 (+60.7) | 13919 (+73.5) |
| BURNIE_3d-linear | OOS | arb | -460 (-477.6) | -458 (-474.7) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) |
| BURNIE_3d-linear | OOS | benign+arb | 28426 (+131.0) | 28458 (+131.1) | 28487 (+132.5) | 11211 (+51.7) | 13304 (+69.6) |
| BURNIE_3d-linear | OOS | benign+arb+mom | 52060 (+142.0) | 52090 (+142.1) | 48397 (+132.7) | 26891 (+73.8) | 24833 (+76.9) |
| BURNIE_3d-bridge | OOS | benign | 28802 (+134.8) | 28840 (+135.0) | 30058 (+142.5) | 14678 (+69.0) | 13216 (+73.3) |
| BURNIE_3d-bridge | OOS | arb | -489 (-508.3) | -486 (-505.4) | 0 (+0.0) | 0 (+0.0) | 0 (+0.0) |
| BURNIE_3d-bridge | OOS | benign+arb | 26295 (+120.8) | 26339 (+121.0) | 28407 (+131.5) | 14173 (+65.2) | 13725 (+73.4) |
| BURNIE_3d-bridge | OOS | benign+arb+mom | 58170 (+145.8) | 58193 (+145.8) | 57261 (+143.9) | 37062 (+93.0) | 29431 (+84.7) |

### OUTAGE (10-min keeper freeze at the largest 10-min move), benign+arb+mom, Mode A, arb budget $5k: LP PnL $ with P1 / without P1

| tape | V1-deployed | V1-kind1 | V2-default | V2-tuned-B | V2-tuned-A | V1-deployed+guard |
|---|---|---|---|---|---|---|
| SOL_calm | -12 / -12 | -12 / -12 | 0 / -8 | 0 / -15 | -13 / -19 | 3 / -12 |
| SOL_volatile | -50 / -50 | -50 / -50 | 122 / 122 | -31 / 113 | 62 / -147 | -50 / -50 |
| JUP_calm | -44 / -44 | -44 / -44 | 0 / -31 | 0 / 185 | 176 / 117 | -6 / -44 |
| JUP_volatile | -1691 / -1691 | -1691 / -1691 | -1574 / -1654 | -4039 / -3954 | -1156 / -1133 | -1691 / -1691 |
| TRUMP_calm | -44 / -44 | -44 / -44 | 0 / -16 | 0 / -28 | 170 / 167 | -18 / -44 |
| TRUMP_volatile | -25052 / -25052 | -25052 / -25052 | -13824 / -13824 | -29748 / -29748 | -3321 / -3000 | -25042 / -25052 |
| PENGU_calm | -50 / -50 | -50 / -50 | -42 / -42 | 212 / 219 | 212 / 143 | -50 / -50 |
| PENGU_volatile | -1297 / -1297 | -1297 / -1297 | -830 / -1144 | -774 / -462 | -184 / -446 | -1206 / -1297 |
| BURNIE_3d-linear | -177 / -177 | -177 / -177 | 2160 / 2481 | 4143 / 4143 | 2680 / 2472 | -178 / -177 |
| BURNIE_3d-bridge | -22280 / -22280 | -22280 / -22280 | -10557 / -10557 | -17519 / -17519 | 3236 / 3113 | -22280 / -22280 |

### OUTAGE (10-min keeper freeze at the largest 10-min move), benign+arb+mom, Mode B, arb budget $5k: LP PnL $ with P1 / without P1

| tape | V1-deployed | V1-kind1 | V2-default | V2-tuned-B | V2-tuned-A | V1-deployed+guard |
|---|---|---|---|---|---|---|
| SOL_calm | 18312 / 18312 | 18321 / 18321 | 15518 / 15556 | 7842 / 7834 | 7039 / 7064 | 18245 / 18312 |
| SOL_volatile | 20607 / 20607 | 20619 / 20619 | 18283 / 18643 | 10417 / 10951 | 8281 / 8054 | 20398 / 20607 |
| JUP_calm | 17662 / 17662 | 17673 / 17673 | 14601 / 14641 | 6878 / 6689 | 7321 / 7370 | 17430 / 17662 |
| JUP_volatile | 11887 / 11887 | 11900 / 11900 | 11052 / 11257 | 4095 / 4280 | 7761 / 7783 | 11802 / 11887 |
| TRUMP_calm | 17801 / 17801 | 17808 / 17808 | 15357 / 15605 | 8329 / 8663 | 7482 / 7527 | 17654 / 17801 |
| TRUMP_volatile | 10356 / 10356 | 10381 / 10381 | 10280 / 11525 | 2582 / 4027 | 5984 / 6408 | 9081 / 10356 |
| PENGU_calm | 20879 / 20879 | 20884 / 20884 | 17207 / 17261 | 7587 / 7683 | 8965 / 8929 | 20837 / 20879 |
| PENGU_volatile | 23844 / 23844 | 23853 / 23853 | 20917 / 21768 | 13316 / 14102 | 9249 / 8987 | 22957 / 23844 |
| BURNIE_3d-linear | 52060 / 52060 | 52090 / 52090 | 48397 / 48294 | 26891 / 26683 | 24833 / 24611 | 52601 / 52060 |
| BURNIE_3d-bridge | 58170 / 58170 | 58193 / 58193 | 57261 / 57866 | 37062 / 37449 | 29431 / 29352 | 57884 / 58170 |

### OUTAGE (10-min keeper freeze at the largest 10-min move), benign+arb+mom, Mode A, arb budget $40k: LP PnL $ with P1 / without P1

| tape | V1-deployed | V1-kind1 | V2-default | V2-tuned-B | V2-tuned-A | V1-deployed+guard |
|---|---|---|---|---|---|---|
| SOL_calm | -27 / -27 | -27 / -27 | 0 / -8 | 0 / -29 | -13 / -18 | 3 / -27 |
| SOL_volatile | 204 / 204 | 204 / 204 | 119 / 119 | 222 / 366 | 75 / -156 | 204 / 204 |
| JUP_calm | -98 / -98 | -98 / -98 | 0 / -30 | 0 / 131 | 176 / 121 | -6 / -98 |
| JUP_volatile | -4234 / -4234 | -4234 / -4234 | -1551 / -1631 | -6309 / -6496 | -1078 / -1057 | -4234 / -4234 |
| TRUMP_calm | -72 / -72 | -72 / -72 | 0 / -16 | 0 / -57 | 170 / 169 | -18 / -72 |
| TRUMP_volatile | -71838 / -71838 | -71838 / -71838 | -13489 / -13489 | -76550 / -76550 | -2878 / -2473 | -71838 / -71838 |
| PENGU_calm | -126 / -126 | -126 / -126 | -41 / -41 | 187 / 143 | 216 / 146 | -126 / -126 |
| PENGU_volatile | -3019 / -3019 | -3019 / -3019 | -814 / -1126 | -2278 / -2183 | -154 / -406 | -2711 / -3019 |
| BURNIE_3d-linear | 313 / 313 | 313 / 313 | 2160 / 2474 | 4696 / 4696 | 2680 / 2472 | -178 / 313 |
| BURNIE_3d-bridge | -42453 / -42453 | -42453 / -42453 | -10335 / -10335 | -37702 / -37702 | 3477 / 3363 | -42453 / -42453 |

### OUTAGE (10-min keeper freeze at the largest 10-min move), benign+arb+mom, Mode B, arb budget $40k: LP PnL $ with P1 / without P1

| tape | V1-deployed | V1-kind1 | V2-default | V2-tuned-B | V2-tuned-A | V1-deployed+guard |
|---|---|---|---|---|---|---|
| SOL_calm | 18312 / 18312 | 18321 / 18321 | 15518 / 15556 | 7842 / 7834 | 7039 / 7064 | 18245 / 18312 |
| SOL_volatile | 20109 / 20109 | 20129 / 20129 | 18283 / 18643 | 9858 / 10378 | 8281 / 8092 | 19900 / 20109 |
| JUP_calm | 17662 / 17662 | 17673 / 17673 | 14601 / 14641 | 6878 / 6703 | 7321 / 7370 | 17430 / 17662 |
| JUP_volatile | 11724 / 11724 | 11750 / 11750 | 11052 / 11257 | 4005 / 4192 | 7761 / 7788 | 11639 / 11724 |
| TRUMP_calm | 17801 / 17801 | 17808 / 17808 | 15357 / 15605 | 8329 / 8663 | 7482 / 7527 | 17654 / 17801 |
| TRUMP_volatile | 7210 / 7210 | 7255 / 7255 | 10280 / 11525 | -387 / 1050 | 5992 / 6437 | 5934 / 7210 |
| PENGU_calm | 20879 / 20879 | 20884 / 20884 | 17207 / 17261 | 7587 / 7682 | 8965 / 8929 | 20837 / 20879 |
| PENGU_volatile | 23770 / 23770 | 23786 / 23786 | 20917 / 21768 | 13316 / 14051 | 9249 / 8990 | 22882 / 23770 |
| BURNIE_3d-linear | 51661 / 51661 | 51696 / 51696 | 48397 / 48293 | 26891 / 26373 | 24833 / 24611 | 52601 / 51661 |
| BURNIE_3d-bridge | 57653 / 57653 | 57691 / 57691 | 57261 / 57866 | 37164 / 37066 | 29431 / 29358 | 58018 / 57653 |

### Robustness — SPLITTING arb (max_fill chunks, same slot), benign+arb+mom, P1, Mode A, push 1.5s: LP PnL $ arb $5k / $40k [benign fill ratio]

| tape | V1-deployed | V1-deployed+guard | V1-deployed+guard25 | V2-default | V2-tuned-B | V2-tuned-A | V2-tuned-A|age25 | V2-tuned-A|age10 |
|---|---|---|---|---|---|---|---|---|
| SOL_calm | 6 / 6 [0.51] | 6 / 6 [0.51] | 6 / 6 [0.51] | 0 / 0 [0.00] | 0 / 0 [0.00] | -28 / -28 [0.85] | -28 / -28 [0.85] | -28 / -28 [0.85] |
| SOL_volatile | -840 / -6499 [0.48] | -840 / -6499 [0.48] | -840 / -6499 [0.48] | -832 / -6496 [0.00] | -832 / -6496 [0.00] | -349 / -394 [0.88] | -349 / -394 [0.88] | -349 / -394 [0.88] |
| JUP_calm | -1 / -1 [0.48] | -1 / -1 [0.48] | -1 / -1 [0.48] | 0 / 0 [0.00] | 0 / 0 [0.00] | 70 / 70 [0.87] | 70 / 70 [0.87] | 70 / 70 [0.87] |
| JUP_volatile | -1774 / -13730! [0.49] | -1774 / -13730! [0.49] | -1774 / -13730! [0.49] | -2100 / -14021! [0.39] | -4166 / -14868! [0.80] | -2321 / -2105 [0.84] | -2321 / -2105 [0.84] | -2321 / -2105 [0.84] |
| TRUMP_calm | 11 / -77 [0.50] | 11 / -77 [0.50] | 11 / -77 [0.50] | -13 / -100 [0.00] | -13 / -100 [0.00] | 150 / 159 [0.88] | 150 / 159 [0.88] | 150 / 159 [0.88] |
| TRUMP_volatile | -34817! / -279288! [0.51] | -34817! / -279288! [0.51] | -34817! / -279288! [0.51] | -36182! / -280704! [0.16] | -42142! / -283058! [0.56] | -8933 / -5253 [0.70] | -8933 / -5253 [0.70] | -8933 / -5253 [0.70] |
| PENGU_calm | -33 / -252 [0.47] | -33 / -252 [0.47] | -33 / -252 [0.47] | -31 / -250 [0.00] | 137 / -33 [0.96] | 105 / 113 [0.89] | 105 / 113 [0.89] | 105 / 113 [0.89] |
| PENGU_volatile | -1231 / -10319! [0.52] | -1231 / -10319! [0.52] | -1231 / -10319! [0.52] | -1299 / -10345! [0.14] | -1979 / -9431 [0.96] | -920 / -669 [0.83] | -920 / -669 [0.83] | -920 / -669 [0.83] |
| BURNIE_3d-linear | -58 / -58 [0.50] | -58 / -58 [0.50] | -58 / -58 [0.50] | 3011 / 3011 [0.45] | 1888 / 1888 [0.97] | 2260 / 2260 [0.85] | 2260 / 2260 [0.85] | 2260 / 2260 [0.85] |
| BURNIE_3d-bridge | -24063! / -180897! [0.50] | -24063! / -180897! [0.50] | -24063! / -180897! [0.50] | -23146! / -178449! [0.34] | -21223! / -163915! [0.95] | 365 / 2538 [0.82] | 365 / 2538 [0.82] | 365 / 2538 [0.82] |

### Robustness — SPLITTING arb (max_fill chunks, same slot), benign+arb+mom, P1, Mode A, push 7s: LP PnL $ arb $5k / $40k [benign fill ratio]

| tape | V1-deployed | V1-deployed+guard | V1-deployed+guard25 | V2-default | V2-tuned-B | V2-tuned-A | V2-tuned-A|age25 | V2-tuned-A|age10 |
|---|---|---|---|---|---|---|---|---|
| SOL_calm | 5 / 5 [0.50] | 5 / 5 [0.50] | 5 / 5 [0.50] | 0 / 0 [0.00] | 0 / 0 [0.00] | -55 / -55 [0.85] | -55 / -55 [0.85] | -17 / -17 [0.74] |
| SOL_volatile | -1656 / -13075! [0.49] | -1656 / -13075! [0.49] | -1656 / -13075! [0.49] | -1425 / -12827! [0.39] | -1631 / -11499! [0.80] | -690 / -687 [0.87] | -690 / -687 [0.87] | -364 / -324 [0.74] |
| JUP_calm | -0 / -0 [0.48] | -0 / -0 [0.48] | -0 / -0 [0.48] | 0 / 0 [0.00] | 0 / 0 [0.00] | 167 / 167 [0.90] | 167 / 167 [0.90] | 82 / 82 [0.76] |
| JUP_volatile | -5426 / -42115! [0.52] | -5426 / -42115! [0.52] | -5426 / -42115! [0.52] | -5713 / -42395! [0.37] | -8809 / -41810! [0.83] | -4996 / -4534 [0.82] | -4996 / -4534 [0.82] | -3830 / -3174 [0.71] |
| TRUMP_calm | -106 / -782 [0.51] | -106 / -782 [0.51] | -106 / -782 [0.51] | -97 / -773 [0.00] | -97 / -773 [0.00] | 150 / 153 [0.89] | 150 / 153 [0.89] | 50 / 76 [0.74] |
| TRUMP_volatile | -46338! / -371611! [0.49] | -46338! / -371611! [0.49] | -46338! / -371611! [0.49] | -47821! / -373061! [0.22] | -52373! / -370494! [0.78] | -18615! / -11302! [0.70] | -18615! / -11302! [0.70] | -15380! / -7768 [0.61] |
| PENGU_calm | -71 / -579 [0.53] | -71 / -579 [0.53] | -71 / -579 [0.53] | -73 / -581 [0.00] | 204 / -228 [0.97] | 171 / 178 [0.88] | 171 / 178 [0.88] | 61 / 77 [0.74] |
| PENGU_volatile | -7293 / -58683! [0.50] | -7293 / -58683! [0.50] | -7293 / -58683! [0.50] | -7453 / -58614! [0.36] | -8383 / -52066! [0.94] | -5245 / -4408 [0.83] | -5245 / -4408 [0.83] | -3762 / -2362 [0.73] |
| BURNIE_3d-linear | -3917 / -29461! [0.49] | -3917 / -29461! [0.49] | -3917 / -29461! [0.49] | -3894 / -29367! [0.00] | -4802 / -25247! [0.07] | 1030 / 1131 [0.85] | 1030 / 1131 [0.85] | 1232 / 1210 [0.72] |
| BURNIE_3d-bridge | -70455! / -525859! [0.51] | -70455! / -525859! [0.51] | -70455! / -525859! [0.51] | -69338! / -520288! [0.39] | -69813! / -483092! [0.93] | -29125! / -13317! [0.81] | -29125! / -13317! [0.81] | -18855! / -7705 [0.68] |

### Robustness — SPLITTING arb (max_fill chunks, same slot), benign+arb+mom, P1, Mode A, push outage: LP PnL $ arb $5k / $40k [benign fill ratio]

| tape | V1-deployed | V1-deployed+guard | V1-deployed+guard25 | V2-default | V2-tuned-B | V2-tuned-A | V2-tuned-A|age25 | V2-tuned-A|age10 |
|---|---|---|---|---|---|---|---|---|
| SOL_calm | -12 / -113 [0.47] | 3 / 3 [0.46] | 3 / 3 [0.46] | 0 / 0 [0.00] | 0 / 0 [0.00] | -13 / -13 [0.83] | -13 / -13 [0.83] | -13 / -13 [0.83] |
| SOL_volatile | -50 / 1316 [0.49] | -50 / 1316 [0.49] | -344 / -2974 [0.49] | 44 / 1341 [0.00] | -31 / 1341 [0.00] | -58 / -64 [0.88] | -55 / -65 [0.88] | -55 / -65 [0.88] |
| JUP_calm | -44 / -420 [0.51] | -6 / -6 [0.51] | -6 / -6 [0.51] | 0 / 0 [0.00] | 0 / 0 [0.00] | 176 / 176 [0.89] | 176 / 176 [0.89] | 176 / 176 [0.89] |
| JUP_volatile | -1691 / -14593! [0.50] | -1691 / -14593! [0.50] | -1629 / -12884! [0.49] | -2321 / -15153! [0.31] | -4039 / -15447! [0.73] | -2227 / -1991 [0.84] | -2227 / -2017 [0.84] | -2227 / -2017 [0.84] |
| TRUMP_calm | -44 / -241 [0.53] | -18 / -18 [0.53] | -18 / -18 [0.53] | 0 / 0 [0.00] | 0 / 0 [0.00] | 170 / 170 [0.87] | 170 / 170 [0.87] | 170 / 170 [0.87] |
| TRUMP_volatile | -25052! / -193685! [0.51] | -25042! / -193685! [0.51] | -25042! / -193685! [0.51] | -25351! / -193933! [0.16] | -29748! / -194450! [0.57] | -8597 / -5235 [0.71] | -8597 / -5235 [0.71] | -8597 / -5235 [0.71] |
| PENGU_calm | -50 / -570 [0.50] | -50 / -570 [0.50] | -29 / -150 [0.49] | -74 / -510 [0.24] | 212 / -196 [0.99] | 153 / 196 [0.89] | 202 / 196 [0.89] | 202 / 196 [0.89] |
| PENGU_volatile | -1297 / -11444! [0.48] | -1206 / -9934 [0.47] | -1206 / -9934 [0.47] | -1312 / -9988 [0.15] | -774 / -8389 [0.96] | -793 / -695 [0.86] | -793 / -697 [0.86] | -793 / -697 [0.86] |
| BURNIE_3d-linear | -177 / 3348 [0.50] | -178 / -178 [0.50] | -178 / -178 [0.50] | 2160 / 2160 [0.30] | 4143 / 5755 [0.64] | 2680 / 2680 [0.86] | 2680 / 2680 [0.86] | 2680 / 2680 [0.86] |
| BURNIE_3d-bridge | -22280! / -171215! [0.49] | -22280! / -171215! [0.49] | -22280! / -171215! [0.49] | -21211! / -168702! [0.33] | -17519! / -161313! [0.94] | 774 / 2895 [0.82] | 774 / 2895 [0.82] | 774 / 2895 [0.82] |

### Robustness — SPLITTING arb (max_fill chunks, same slot), benign+arb+mom, P1, Mode B, push 1.5s: LP PnL $ arb $5k / $40k [benign fill ratio]

| tape | V1-deployed | V1-deployed+guard | V1-deployed+guard25 | V2-default | V2-tuned-B | V2-tuned-A | V2-tuned-A|age25 | V2-tuned-A|age10 |
|---|---|---|---|---|---|---|---|---|
| SOL_calm | 18465 / 18465 [1.00] | 18465 / 18465 [1.00] | 18465 / 18465 [1.00] | 15615 / 15615 [0.99] | 6777 / 6777 [1.00] | 7147 / 7147 [0.85] | 7147 / 7147 [0.85] | 7147 / 7147 [0.85] |
| SOL_volatile | 21367 / 21367 [1.00] | 21367 / 21367 [1.00] | 21367 / 21367 [1.00] | 18786 / 18786 [1.00] | 10848 / 10848 [1.00] | 8335 / 8335 [0.88] | 8335 / 8335 [0.88] | 8335 / 8335 [0.88] |
| JUP_calm | 17803 / 17803 [1.00] | 17803 / 17803 [1.00] | 17803 / 17803 [1.00] | 14655 / 14655 [1.00] | 6592 / 6592 [1.00] | 7139 / 7139 [0.87] | 7139 / 7139 [0.87] | 7139 / 7139 [0.87] |
| JUP_volatile | 9954 / 9954 [0.94] | 9954 / 9954 [0.94] | 9954 / 9954 [0.94] | 9077 / 9077 [0.94] | 2911 / 2911 [0.94] | 7365 / 7365 [0.84] | 7365 / 7365 [0.84] | 7365 / 7365 [0.84] |
| TRUMP_calm | 18436 / 18436 [1.00] | 18436 / 18436 [1.00] | 18436 / 18436 [1.00] | 15814 / 15814 [0.99] | 7784 / 7784 [0.99] | 7667 / 7667 [0.88] | 7667 / 7667 [0.88] | 7667 / 7667 [0.88] |
| TRUMP_volatile | 7776! / 3380! [0.97] | 7776! / 3380! [0.97] | 7776! / 3380! [0.97] | 9039! / 9056! [0.97] | 2219! / -187! [0.97] | 5357 / 5419 [0.70] | 5357 / 5419 [0.70] | 5357 / 5419 [0.70] |
| PENGU_calm | 20085 / 20085 [0.98] | 20085 / 20085 [0.98] | 20085 / 20085 [0.98] | 17150 / 17150 [0.98] | 9487 / 9487 [0.98] | 8407 / 8407 [0.89] | 8407 / 8407 [0.89] | 8407 / 8407 [0.89] |
| PENGU_volatile | 21720 / 21720 [1.00] | 21720 / 21720 [1.00] | 21720 / 21720 [1.00] | 20209 / 20209 [0.99] | 11613 / 11613 [1.00] | 9347 / 9347 [0.83] | 9347 / 9347 [0.83] | 9347 / 9347 [0.83] |
| BURNIE_3d-linear | 52471 / 52471 [0.99] | 52471 / 52471 [0.99] | 52471 / 52471 [0.99] | 49037 / 49037 [0.99] | 27447 / 27447 [0.99] | 24551 / 24551 [0.85] | 24551 / 24551 [0.85] | 24551 / 24551 [0.85] |
| BURNIE_3d-bridge | 58018 / 58018 [0.99] | 58018 / 58018 [0.99] | 58018 / 58018 [0.99] | 56935 / 56935 [0.98] | 37507 / 37507 [0.99] | 28915 / 28915 [0.82] | 28915 / 28915 [0.82] | 28915 / 28915 [0.82] |

### Robustness — SPLITTING arb (max_fill chunks, same slot), benign+arb+mom, P1, Mode B, push 7s: LP PnL $ arb $5k / $40k [benign fill ratio]

| tape | V1-deployed | V1-deployed+guard | V1-deployed+guard25 | V2-default | V2-tuned-B | V2-tuned-A | V2-tuned-A|age25 | V2-tuned-A|age10 |
|---|---|---|---|---|---|---|---|---|
| SOL_calm | 18910 / 18910 [1.00] | 18910 / 18910 [1.00] | 18910 / 18910 [1.00] | 15670 / 15670 [0.99] | 7416 / 7416 [0.99] | 7313 / 7313 [0.85] | 7313 / 7313 [0.85] | 6238 / 6238 [0.74] |
| SOL_volatile | 21622 / 21622 [1.00] | 21622 / 21622 [1.00] | 21622 / 21622 [1.00] | 19304 / 19304 [1.00] | 11339 / 11141 [1.00] | 8268 / 8242 [0.87] | 8268 / 8242 [0.87] | 7182 / 7156 [0.74] |
| JUP_calm | 17330 / 17330 [1.00] | 17330 / 17330 [1.00] | 17330 / 17330 [1.00] | 13818 / 13818 [1.00] | 5797 / 5797 [1.00] | 7192 / 7192 [0.90] | 7192 / 7192 [0.90] | 5838 / 5838 [0.76] |
| JUP_volatile | 10869 / 10869 [0.95] | 10869 / 10869 [0.95] | 10869 / 10869 [0.95] | 10226 / 10226 [0.94] | 3078 / 3078 [0.94] | 7513 / 7513 [0.81] | 7513 / 7513 [0.81] | 6393 / 6393 [0.71] |
| TRUMP_calm | 17928 / 17928 [1.00] | 17928 / 17928 [1.00] | 17928 / 17928 [1.00] | 15778 / 15778 [0.99] | 8596 / 8596 [1.00] | 7586 / 7586 [0.89] | 7586 / 7586 [0.89] | 6039 / 6039 [0.74] |
| TRUMP_volatile | 11221! / 4981! [0.98] | 11221! / 4981! [0.98] | 11221! / 4981! [0.98] | 13564! / 13506! [0.98] | 7632! / 9579! [0.98] | 6071 / 6112 [0.70] | 6071 / 6112 [0.70] | 5843 / 5867 [0.63] |
| PENGU_calm | 20545 / 20545 [1.00] | 20545 / 20545 [1.00] | 20545 / 20545 [1.00] | 17199 / 17199 [0.99] | 7617 / 7617 [1.00] | 8780 / 8780 [0.88] | 8780 / 8780 [0.88] | 6944 / 6944 [0.74] |
| PENGU_volatile | 19526 / 19526 [0.98] | 19526 / 19526 [0.98] | 19526 / 19526 [0.98] | 18281 / 18281 [0.98] | 9936 / 9891 [0.98] | 8806 / 8806 [0.83] | 8806 / 8806 [0.83] | 7830 / 7830 [0.73] |
| BURNIE_3d-linear | 48871 / 48871 [0.99] | 48871 / 48871 [0.99] | 48871 / 48871 [0.99] | 45069 / 45069 [0.99] | 25078 / 25078 [0.99] | 23817 / 23817 [0.85] | 23817 / 23817 [0.85] | 20111 / 20111 [0.72] |
| BURNIE_3d-bridge | 56065 / 56065 [0.99] | 56065 / 56065 [0.99] | 56065 / 56065 [0.99] | 54736 / 54736 [0.99] | 32369 / 32369 [0.99] | 28721 / 28721 [0.82] | 28721 / 28721 [0.82] | 23975 / 23975 [0.69] |

### Robustness — SPLITTING arb (max_fill chunks, same slot), benign+arb+mom, P1, Mode B, push outage: LP PnL $ arb $5k / $40k [benign fill ratio]

| tape | V1-deployed | V1-deployed+guard | V1-deployed+guard25 | V2-default | V2-tuned-B | V2-tuned-A | V2-tuned-A|age25 | V2-tuned-A|age10 |
|---|---|---|---|---|---|---|---|---|
| SOL_calm | 18312 / 18312 [0.98] | 18245 / 18245 [0.98] | 18243 / 18243 [0.98] | 15518 / 15518 [0.97] | 7842 / 7842 [0.98] | 7039 / 7039 [0.83] | 7039 / 7039 [0.83] | 7039 / 7039 [0.83] |
| SOL_volatile | 20607 / 17194 [1.00] | 20398 / 18151 [1.00] | 20394 / 18155 [1.00] | 18156 / 17443 [1.00] | 10417 / 8574 [1.00] | 8281 / 8281 [0.88] | 8297 / 8297 [0.88] | 8297 / 8297 [0.88] |
| JUP_calm | 17662 / 17662 [1.00] | 17430 / 17430 [0.98] | 17421 / 17421 [0.98] | 14601 / 14601 [0.98] | 6878 / 6878 [0.99] | 7321 / 7321 [0.89] | 7315 / 7315 [0.89] | 7315 / 7315 [0.89] |
| JUP_volatile | 11887 / 11061 [0.96] | 11802 / 10834 [0.96] | 11802 / 10834 [0.96] | 11052 / 11052 [0.95] | 4095 / 3091 [0.96] | 7761 / 7761 [0.85] | 7761 / 7761 [0.85] | 7761 / 7761 [0.85] |
| TRUMP_calm | 17801 / 17801 [0.99] | 17654 / 17654 [0.99] | 17639 / 17639 [0.98] | 15357 / 15357 [0.98] | 8329 / 8329 [0.98] | 7482 / 7482 [0.87] | 7478 / 7478 [0.87] | 7478 / 7478 [0.87] |
| TRUMP_volatile | 10356! / 2237! [0.98] | 9081! / 962! [0.98] | 8965! / 846! [0.98] | 9748! / 3165! [0.98] | 2582! / -5436! [0.98] | 5913 / 5885 [0.71] | 5913 / 5885 [0.71] | 5913 / 5885 [0.71] |
| PENGU_calm | 20879 / 20879 [1.01] | 20837 / 20837 [1.00] | 20825 / 20825 [1.00] | 17207 / 17207 [0.99] | 7587 / 7587 [1.00] | 8965 / 8965 [0.89] | 8937 / 8937 [0.89] | 8937 / 8937 [0.89] |
| PENGU_volatile | 23844 / 23198 [1.00] | 22957 / 22920 [0.99] | 22957 / 22920 [0.99] | 20917 / 20917 [0.99] | 13316 / 13316 [0.99] | 9249 / 9249 [0.86] | 9241 / 9241 [0.86] | 9241 / 9241 [0.86] |
| BURNIE_3d-linear | 52060 / 51331 [1.00] | 52601 / 52601 [1.00] | 52602 / 52602 [1.00] | 48397 / 48397 [1.00] | 26891 / 26891 [1.00] | 24833 / 24833 [0.86] | 24833 / 24833 [0.86] | 24833 / 24833 [0.86] |
| BURNIE_3d-bridge | 58170 / 57653 [0.98] | 57884 / 58018 [0.98] | 57868 / 57955 [0.98] | 57483 / 57750 [0.98] | 37062 / 37164 [0.98] | 29429 / 29429 [0.82] | 29429 / 29429 [0.82] | 29429 / 29429 [0.82] |

### observed_stale_slots: benign trades falsely refused (Custom 8002) with a LIVE keeper (1.5 s pushes), V2-default otherwise; % of benign attempts, [2/min | 10/min], no-P1 (P1 identical if equal)

| tape | N=0 | N=150 | N=375 | N=750 | N=1500 | N=3000 |
|---|---|---|---|---|---|---|
| SOL_calm | 0.00% / 0.00% | 5.63% / 0.46% | 0.58% / 0.00% | 0.00% / 0.00% | 0.00% / 0.00% | 0.00% / 0.00% |
| SOL_volatile | 0.00% / 0.00% | 0.38% / 0.03% | 0.00% / 0.00% | 0.00% / 0.00% | 0.00% / 0.00% | 0.00% / 0.00% |
| JUP_calm | 0.00% / 0.00% | 33.61% / 45.38% | 17.47% / 21.16% | 5.88% / 6.99% | 1.16% / 1.68% | 0.00% / 0.02% |
| JUP_volatile | 0.00% / 0.00% | 1.69% / 1.04% | 0.24% / 0.10% | 0.00% / 0.00% | 0.00% / 0.00% | 0.00% / 0.00% |
| TRUMP_calm | 0.00% / 0.00% | 15.47% / 16.67% | 4.41% / 2.62% | 0.59% / 0.14% | 0.00% / 0.00% | 0.00% / 0.00% |
| TRUMP_volatile | 0.00% / 0.00% | 0.11% / 0.00% | 0.00% / 0.00% | 0.00% / 0.00% | 0.00% / 0.00% | 0.00% / 0.00% |
| PENGU_calm | 0.00% / 0.00% | 1.74% / 0.82% | 0.10% / 0.01% | 0.00% / 0.00% | 0.00% / 0.00% | 0.00% / 0.00% |
| PENGU_volatile | 0.00% / 0.00% | 0.17% / 0.01% | 0.03% / 0.00% | 0.00% / 0.00% | 0.00% / 0.00% | 0.00% / 0.00% |
| BURNIE_3d-linear | 0.00% / 0.00% | 51.45% / 62.78% | 38.17% / 47.03% | 24.71% / 30.77% | 11.78% / 14.65% | 2.52% / 3.68% |
| BURNIE_3d-bridge | 0.00% / 0.00% | 1.33% / 0.25% | 0.16% / 0.13% | 0.00% / 0.01% | 0.00% / 0.00% | 0.00% / 0.00% |

### observed_stale_slots in the OUTAGE (no P1, benign+arb+mom, Mode A): LP PnL $ and loss avoided vs N=0 (disabled)

| tape | N=0 | N=150 | N=375 | N=750 | N=1500 | N=3000 |
|---|---|---|---|---|---|---|
| SOL_calm | -8 (+0) | -8 (+0) | -8 (+0) | -8 (+0) | -8 (+0) | -8 (+0) |
| SOL_volatile | 122 (+0) | 122 (+0) | 122 (+0) | 122 (+0) | 122 (+0) | 122 (+0) |
| JUP_calm | -31 (+0) | -31 (+0) | -31 (+0) | -31 (+0) | -31 (+0) | -31 (+0) |
| JUP_volatile | -1654 (+0) | -1579 (+75) | -1588 (+66) | -1588 (+66) | -1654 (+0) | -1654 (+0) |
| TRUMP_calm | -16 (+0) | -16 (+0) | -16 (+0) | -16 (+0) | -16 (+0) | -16 (+0) |
| TRUMP_volatile | -13824 (+0) | -13772 (+53) | -13804 (+20) | -13824 (+0) | -13824 (+0) | -13824 (+0) |
| PENGU_calm | -42 (+0) | -42 (+0) | -42 (+0) | -42 (+0) | -42 (+0) | -42 (+0) |
| PENGU_volatile | -1144 (+0) | -808 (+336) | -876 (+268) | -874 (+270) | -1144 (+0) | -1144 (+0) |
| BURNIE_3d-linear | 2481 (+0) | 770 (-1711) | 1572 (-909) | 2288 (-193) | 2308 (-173) | 2347 (-134) |
| BURNIE_3d-bridge | -10557 (+0) | -10575 (-17) | -10526 (+32) | -10557 (+0) | -10557 (+0) | -10557 (+0) |

### observed_stale_slots in the OUTAGE (no P1, benign+arb+mom, Mode B): LP PnL $ and loss avoided vs N=0 (disabled)

| tape | N=0 | N=150 | N=375 | N=750 | N=1500 | N=3000 |
|---|---|---|---|---|---|---|
| SOL_calm | 15556 (+0) | 15039 (-518) | 15505 (-51) | 15525 (-32) | 15556 (+0) | 15556 (+0) |
| SOL_volatile | 18643 (+0) | 18283 (-360) | 18487 (-156) | 18621 (-22) | 18643 (+0) | 18643 (+0) |
| JUP_calm | 14641 (+0) | 8223 (-6418) | 11845 (-2796) | 14184 (-457) | 14535 (-106) | 14641 (+0) |
| JUP_volatile | 11257 (+0) | 12261 (+1004) | 11142 (-115) | 11075 (-182) | 11257 (+0) | 11257 (+0) |
| TRUMP_calm | 15605 (+0) | 11975 (-3630) | 14727 (-878) | 15518 (-87) | 15605 (+0) | 15605 (+0) |
| TRUMP_volatile | 11525 (+0) | 10280 (-1245) | 10301 (-1224) | 10467 (-1058) | 11525 (+0) | 11525 (+0) |
| PENGU_calm | 17261 (+0) | 16959 (-302) | 17214 (-47) | 17221 (-40) | 17261 (+0) | 17261 (+0) |
| PENGU_volatile | 21768 (+0) | 20839 (-929) | 20917 (-851) | 21418 (-351) | 21768 (+0) | 21768 (+0) |
| BURNIE_3d-linear | 48294 (+0) | 22916 (-25378) | 31986 (-16308) | 38977 (-9317) | 41787 (-6507) | 46870 (-1424) |
| BURNIE_3d-bridge | 57866 (+0) | 57383 (-483) | 57442 (-424) | 57556 (-310) | 57866 (+0) | 57866 (+0) |


---
matcher git SHA: `49fb7dc77c0c094533ca75cfa2e040f8a53e675c`; uncommitted src diff sha256[..16] + status: `e3b0c44298fc1c14`; total runtime 89.7s; quick=false

### Mode B search

3240 candidates, 232 feasible (benign all-in cost <= 60 bps). Chosen: `max_total=400 fee_lo=10 fee_hi=250 fee_cold=default(80,clamped) vol_a_milli=1000 vol_b_den=100 vol_ref_slots=25 skew_mult=100 thin_rebate=0 impact_k=0 liq=10x_capital max_fill=max_inv/4 max_mark_age=150 observed_stale=0`

in-sample worst $2108.78, sum $30149.96, benign cost 58.13 bps. Search time 66.7s.

Top 10 feasible (worst-case in-sample $):

| rank | params | worst $ | sum $ | benign bps |
|---|---|---|---|---|
| 1 | max_total=400 fee_lo=10 fee_hi=100 fee_cold=default(80,clamped) vol_a_milli=1000 vol_b_den=100 vol_ref_slots=25 skew_mult=100 thin_rebate=0 impact_k=0 liq=10x_capital max_fill=max_inv/4 max_mark_age=150 observed_stale=0 | 2108.78 | 30121.06 | 58.1 |
| 2 | max_total=400 fee_lo=10 fee_hi=150 fee_cold=default(80,clamped) vol_a_milli=1000 vol_b_den=100 vol_ref_slots=25 skew_mult=100 thin_rebate=0 impact_k=0 liq=10x_capital max_fill=max_inv/4 max_mark_age=150 observed_stale=0 | 2108.78 | 30144.97 | 58.1 |
| 3 | max_total=400 fee_lo=10 fee_hi=250 fee_cold=default(80,clamped) vol_a_milli=1000 vol_b_den=100 vol_ref_slots=25 skew_mult=100 thin_rebate=0 impact_k=0 liq=10x_capital max_fill=max_inv/4 max_mark_age=150 observed_stale=0 | 2108.78 | 30149.96 | 58.1 |
| 4 | max_total=400 fee_lo=10 fee_hi=100 fee_cold=default(80,clamped) vol_a_milli=1000 vol_b_den=200 vol_ref_slots=25 skew_mult=100 thin_rebate=0 impact_k=0 liq=10x_capital max_fill=max_inv/4 max_mark_age=150 observed_stale=0 | 2075.12 | 30024.27 | 57.9 |
| 5 | max_total=400 fee_lo=10 fee_hi=150 fee_cold=default(80,clamped) vol_a_milli=1000 vol_b_den=200 vol_ref_slots=25 skew_mult=100 thin_rebate=0 impact_k=0 liq=10x_capital max_fill=max_inv/4 max_mark_age=150 observed_stale=0 | 2075.12 | 30033.53 | 57.9 |
| 6 | max_total=400 fee_lo=10 fee_hi=250 fee_cold=default(80,clamped) vol_a_milli=1000 vol_b_den=200 vol_ref_slots=25 skew_mult=100 thin_rebate=0 impact_k=0 liq=10x_capital max_fill=max_inv/4 max_mark_age=150 observed_stale=0 | 2075.12 | 30033.53 | 57.9 |
| 7 | max_total=400 fee_lo=10 fee_hi=100 fee_cold=default(80,clamped) vol_a_milli=1000 vol_b_den=0 vol_ref_slots=25 skew_mult=100 thin_rebate=0 impact_k=0 liq=10x_capital max_fill=max_inv/4 max_mark_age=150 observed_stale=0 | 2059.72 | 29961.51 | 57.8 |
| 8 | max_total=400 fee_lo=10 fee_hi=150 fee_cold=default(80,clamped) vol_a_milli=1000 vol_b_den=0 vol_ref_slots=25 skew_mult=100 thin_rebate=0 impact_k=0 liq=10x_capital max_fill=max_inv/4 max_mark_age=150 observed_stale=0 | 2059.72 | 29961.70 | 57.8 |
| 9 | max_total=400 fee_lo=10 fee_hi=250 fee_cold=default(80,clamped) vol_a_milli=1000 vol_b_den=0 vol_ref_slots=25 skew_mult=100 thin_rebate=0 impact_k=0 liq=10x_capital max_fill=max_inv/4 max_mark_age=150 observed_stale=0 | 2059.72 | 29961.70 | 57.8 |
| 10 | max_total=400 fee_lo=20 fee_hi=100 fee_cold=default(80,clamped) vol_a_milli=500 vol_b_den=100 vol_ref_slots=25 skew_mult=100 thin_rebate=50 impact_k=0 liq=10x_capital max_fill=max_inv/4 max_mark_age=150 observed_stale=0 | 1954.28 | 31195.80 | 60.0 |

### Mode A search

252 candidates. Chosen (max worst-case Mode-A LP PnL s.t. benign filled/requested notional >= 90%): `max_total=100 fee_lo=10 fee_hi=80 fee_cold=10 vol_a_milli=1000 vol_b_den=100 vol_ref_slots=25 skew_mult=300 thin_rebate=150 impact_k=5000 liq=10x_capital max_fill=max_inv/4 max_mark_age=150 observed_stale=0`

in-sample worst $-1055.04, sum $-1160.53, benign fill ratio 0.909. Search time 3.1s.

V2-tuned-B ctx (SOL_calm open): kind=2 trading_fee_bps=10 base_spread_bps=20 max_total_bps=400 impact_k_bps=0 liquidity_notional_e6=100000000000 skew_spread_mult_bps=100 max_fill_abs=132625994 max_inventory_abs=530503978

`Some(V2Config { flags: 1, fee_lo_bps: 10, fee_hi_bps: 250, fee_cold_bps: 80, vol_a_milli: 1000, vol_b_den: 100, vol_alpha_bps: 1000, vol_warmup: 0, vol_move_cap_10bps: 100, vol_ref_slots: 25, thin_rebate_mult_bps: 0, skew_cap_bps: 300, rebate_cap_bps: 150, max_mark_age_slots: 150, observed_stale_slots: 0, skew_ref_inventory: 530503978 })`

V2-tuned-A ctx (SOL_calm open): kind=2 trading_fee_bps=10 base_spread_bps=20 max_total_bps=100 impact_k_bps=5000 liquidity_notional_e6=100000000000 skew_spread_mult_bps=300 max_fill_abs=132625994 max_inventory_abs=530503978

`Some(V2Config { flags: 1, fee_lo_bps: 10, fee_hi_bps: 80, fee_cold_bps: 10, vol_a_milli: 1000, vol_b_den: 100, vol_alpha_bps: 1000, vol_warmup: 0, vol_move_cap_10bps: 100, vol_ref_slots: 25, thin_rebate_mult_bps: 150, skew_cap_bps: 100, rebate_cap_bps: 50, max_mark_age_slots: 150, observed_stale_slots: 0, skew_ref_inventory: 530503978 })`

---
matcher git SHA: `49fb7dc77c0c094533ca75cfa2e040f8a53e675c`; uncommitted src diff sha256[..16] + status: `e3b0c44298fc1c14`; total runtime 89.7s; quick=false
