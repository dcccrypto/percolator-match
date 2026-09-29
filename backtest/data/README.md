# Backtest price data

Fetched 2026-09-29 18:46 UTC. Public endpoints only, no keys. All CSVs: header `ts_ms,price` (ts = bar open time, UTC ms; price = bar close, USD/USDT, float). Missing bars forward-filled from the previous close.

## 1. Binance spot 1-second klines

Source: `https://api.binance.com/api/v3/klines?symbol={SYM}USDT&interval=1s&limit=1000&startTime={ms}&endTime={ms}` (87 paged requests/day, 100 ms sleep). Quote is USDT (treated as USD).

Day selection: `interval=1d&limit=121` daily klines, today's incomplete candle dropped (120 complete days). Daily range % = (high-low)/open×100. **volatile** = max-range day, **calm** = min-range day in that window. Each file covers 00:00:00–23:59:59 UTC of the date = 86,400 rows.

Realized vol = population stdev of 1-s log returns × sqrt(86400), as daily %. "Range %" columns: `1d` from the daily kline (high/low incl. wicks); `file` = (max close − min close)/first close.

| file | symbol | window (UTC) | rows | ffilled | min | max | range % (1d kline) | range % (file closes) | realized vol (daily %) | median 1d range, 120d |
|---|---|---|---|---|---|---|---|---|---|---|
| `SOL_volatile_20260822.csv` | SOLUSDT | volatile 2026-08-22 | 86400 | 0 | 87.97 | 102.71 | 16.03 | 15.72 | 6.52 | 4.06 |
| `SOL_calm_20260815.csv` | SOLUSDT | calm 2026-08-15 | 86400 | 0 | 75.05 | 75.74 | 0.92 | 0.92 | 1.71 | 4.06 |
| `JUP_volatile_20260906.csv` | JUPUSDT | volatile 2026-09-06 | 86400 | 0 | 0.2181 | 0.2833 | 29.73 | 29.64 | 10.82 | 7.36 |
| `JUP_calm_20260817.csv` | JUPUSDT | calm 2026-08-17 | 86400 | 0 | 0.1669 | 0.1707 | 2.27 | 2.27 | 2.17 | 7.36 |
| `TRUMP_volatile_20260822.csv` | TRUMPUSDT | volatile 2026-08-22 | 86400 | 0 | 1.851 | 3.672 | 97.91 | 97.48 | 41.20 | 6.18 |
| `TRUMP_calm_20260721.csv` | TRUMPUSDT | calm 2026-07-21 | 86400 | 0 | 1.585 | 1.614 | 1.82 | 1.82 | 3.21 | 6.18 |
| `PENGU_volatile_20260823.csv` | PENGUUSDT | volatile 2026-08-23 | 86400 | 0 | 0.008034 | 0.010346 | 27.56 | 27.51 | 11.05 | 6.72 |
| `PENGU_calm_20260807.csv` | PENGUUSDT | calm 2026-08-07 | 86400 | 0 | 0.005955 | 0.006101 | 2.44 | 2.44 | 2.50 | 6.72 |

## 2. BURNIE (Solana memecoin) 1-minute tape

Found via `https://api.geckoterminal.com/api/v2/search/pools?query=BURNIE&network=solana`; most liquid pool taken. This is the **same pool the Percolator keeper reads for the BURNIE market** (`registry.json` poolAddress `5tYFviFW…`, mainnetCa `CGEDT9QZ…pump`).

- Pool: `5tYFviFWQRKV9BJSTHGitbdqEYC1BGUgRUDnSADUXqJP` (BURNIE / SOL, DEX pumpswap), created 2026-04-03T03:08:37Z
- Base token mint: `CGEDT9QZDvvH5GmVkWJH2BXiMJqMJySC9ihWyr7Spump`
- Liquidity (reserve_in_usd) at fetch: $265,203
- 24h volume (volume_usd.h24) at fetch: $69,654
- FDV: $1,503,948; 24h txns: 211 buys / 253 sells (109 buyers / 137 sellers)
- Source: `https://api.geckoterminal.com/api/v2/networks/solana/pools/{pool}/ohlcv/minute?aggregate=1&limit=1000&before_timestamp={s}&currency=usd` (2.5 s between calls). Price = USD close (pool is BURNIE/SOL; GeckoTerminal converts to USD via SOL/USD).

| file | window (UTC) | rows | raw 1m bars (had trades) | ffilled | min | max | range % | realized vol (daily %, 1-min returns × sqrt(1440)) |
|---|---|---|---|---|---|---|---|---|
| `BURNIE_1m_20260926T1845_20260929T1826.csv` | last 3 days to fetch time | 4302 | 869 | 3433 | 0.00138288 | 0.00177427 | 23.54 | 18.73 |

Caveat: GeckoTerminal only emits a bar for minutes with trades, so ~80% of minutes are forward-filled (flat). Realized vol from this tape is computed over the forward-filled series; the tape is trade-driven/jumpy, not a continuous quote.

## 3. Percolator keeper price pushes

**Not found — no per-market push price series exists locally.** Checked (read-only):
- `~/percolator-oracle-keeper/logs/keeper.out.log` (120 MB) and `keeper.err.log` (1.2 GB): the keeper logs only `=== Cycle N <iso ts> ===` and `[loop] batched push × N: sig=…` (count of markets + truncated signature), never the pushed price per market. The only price-bearing lines are circuit-breaker messages printed with 2 decimals (useless for memecoins).
- keeper `src/` / `scripts/`: the only file write is `registry.json`; no sqlite/json price persistence.
- `~/.openclaw/data/*.db` (fibbot, manchester, percolator, proclean, system, upwork): all have the same agent-ops schema (tasks, messages, agent_activity, health_checks, token_usage, cost_tracking, system_snapshots, transcripts, sprints, subagent_events, compaction_events) — no push/price/mark tables.

Push cadence (from cycle timestamps preceding each `batched push` line in keeper.out.log, since 2026-09-24 re-seed): 326,628 batched-push transactions; **median interval 1.50 s** (p10 1.50 s, p90 1.50 s, mean 1.53 s; last 24h: 55,875 pushes, median 1.50 s, max gap 67.6 s). Each batched tx pushes ~18–19 markets at once, so per-market cadence ≈ 1.5 s when the market is priced (markets can be skipped in a cycle on RPC errors/quarantine). Note: this is devnet push of mainnet DEX prices; no `keeper_pushes_*.csv` files were produced.

If you need the actual pushed series, it would have to be reconstructed on-chain (devnet tx history of keeper `FbTbDeGWQpjrEqJdqoBHX3sTWHoAmU2xywD7wyxH6WC7`) — not done here.

## Size

Total CSV size 14.6 MB (not gzipped; threshold was 60 MB).
