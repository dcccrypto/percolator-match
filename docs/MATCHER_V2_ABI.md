# P1 ↔ P2 interface: matcher call extension (LP headroom, mark slot, fee request)

Owner: Anvil (P2 matcher v2). Consumers: the P1 wrapper (`percolator-prog` branch `feat/p1-safety-release`), the SDK, and the wizard/seed.
Source of truth: `percolator-match` branch `feat/p2-matcher-v2`, `src/v2.rs` (`CallExt`) and `src/lib.rs`. This doc is authoritative for the wire format. If code and doc disagree, the code wins, and please tell Anvil.

## 1. Where the bytes go

Tag-0 call, 67 bytes (unchanged ABI v3 layout):
- `[0]` tag = 0
- `[1..9]` req_id
- `[9..11]` asset_index
- `[11..19]` lp_account_id
- `[19..27]` oracle_price_e6
- `[27..43]` req_size i128
- `[43..67]` **24-byte extension** (was "must be zero")

Tag-3 batch: `18 + 26·n` bytes is legacy. `18 + 26·n + 24·n` is legs followed by one 24-byte extension per leg, in leg order. Any other length is rejected.

## 2. Extension block (24 bytes, little-endian)

| off (in block) | abs (tag 0) | type | field | rule |
|---|---|---|---|---|
| 0 | 43 | u8 | `ext_version` | 0 = legacy (all 24 bytes must be 0); 1 = this layout; anything else is rejected |
| 1 | 44 | u8 | `ext_flags` | bit0 `HEADROOM`, bit1 `MARK_SLOT`, bit2 `ACCEPTS_FEE_REQUEST`, bit3 `TAKER_REDUCING`, bit4 `EXEC_BAND`; bits 5..7 must be 0 |
| 2..4 | 45..47 | u16 | `exec_band_bps` | the wrapper's oracle band on exec_price; must be 0 unless `EXEC_BAND` is set |
| 4..12 | 47..55 | u64 | `mark_slot` | slot of the last *fresh oracle observation* behind `oracle_price_e6` (for AUTH_MARK: the push slot, e.g. `last_good_oracle_slot`); must be 0 unless `MARK_SLOT` is set |
| 12..20 | 55..63 | u64 | `lp_headroom_q` | max \|exec_size\| (base q) the wrapper will accept **in this request's direction** without the LP failing its cap/margin; `u64::MAX` = unbounded; 0 = zero-fill; must be 0 unless `HEADROOM` is set |
| 20..24 | 63..67 | u32 | reserved | must be 0 |

Matcher behaviour:
- **HEADROOM.** The fill is clipped to `headroom − already_filled_this_batch(asset, direction)`. At 0 the call returns a zero-fill (`exec_size = 0`, `exec_price = oracle`, `FLAG_PARTIAL_OK`), so the wrapper does not revert with Custom(49). This applies to every matcher kind.
- **MARK_SLOT.** If the ctx has a v2 block with `max_mark_age_slots > 0` and `Clock.slot − mark_slot > max_mark_age_slots`, the CPI fails with `Custom(8002)` ERR_STALE_MARK. `mark_slot > Clock.slot` fails with `Custom(8003)`. Optionally (ctx flag `STALE_ALLOW_REDUCING`) the matcher still fills trades that reduce the LP's inventory, clipped so they cannot flip it.
- **TAKER_REDUCING** (added after security review P2-1). The wrapper attests the request only reduces the *taker's* existing position and cannot open or flip it. Under a stale mark, and when the ctx allows reducing fills (the kind-2 default), the fill goes through unclipped, so traders can always exit. Without it, only fills that reduce the *LP's* inventory are let through under a stale mark (clipped to |LP inventory|). The matcher cannot see the taker's position.
- **EXEC_BAND** (added after P2-2). The matcher prices within `min(max_total_bps, exec_band_bps)`: kind 2 clips size, and kinds 0/1 clamp their spread. A banded P1 wrapper therefore gets a partial fill instead of reverting with Custom(66).
- **ACCEPTS_FEE_REQUEST.** On a non-zero fill, return `flags` bits 22..31 carry `requested_fee_bps = ceil(|exec−oracle|·1e4/oracle)`, capped at 1023. That is the matcher's quote expressed as a fee on mark-settled notional. Without this flag those bits are always 0.

## 3. Why the fee-request channel exists (security review C-1, verified)

On v18.2 the wrapper settles every fill at the asset mark. See `src/v16_program.rs:11722-11752` (F-TRADENOCPI-FEE): `TradeRequestV16.exec_price = effective_price`. The matcher's `exec_price` is used only for:
- the taker `limit_price` check;
- hybrid/EWMA mark discovery;
- the batch slippage cap.

So any spread the matcher quotes (fixed, adaptive, impact or skew) **pays the LP nothing today**. Only the matcher's quantity decisions reach the engine: size clip, headroom clip and stale refusal.

For P2's adaptive fee, impact and skew to become economic, the wrapper has to charge the quote. Recommended P1/P3 wiring:
- Set `ACCEPTS_FEE_REQUEST`.
- Read `ret.flags` bits 22..31 and add `KNOWN_FLAGS |= FLAG_REQUESTED_FEE_MASK` in `validate_matcher_return`.
- Charge the taker `requested_fee_bps × mark notional`. Route it to the LP portfolio, or to the vault-owned LP's NAV in P3.
- Bound it by a protocol maximum.

The routing decision is the wrapper's. Charging it through the existing split (only 48% of it reaches the Earn vault, which is not the LP today) would **not** pay the LP.

## 4. When should the wrapper send an extension?

Recommended rule: send `ext_version = 1` iff both hold:
- `ctx[64..72] == "PERCMATC"` magic (u64 LE `0x5045_5243_4d41_5443`);
- `ctx[64+178] == 1`, the v2-block marker.

That byte is 0 on every context created by the deployed v1 matcher (`4seJWjv3` @ `12bd671`). It is 1 on:
- every kind-2 context;
- any kind 0/1 context whose owner enabled the v2 block with tag 5.

The rule makes the rollout order-independent:
- A v1 program never gets a non-zero extension. The v1 matcher rejects non-zero bytes 43..67 with InvalidInstructionData, which would brick every CPI trade.
- A v2 program accepts both forms.

Alternative: allowlist the v2 program ID. Do **not** send the extension unconditionally while any v1 matcher is still deployed.

## 5. Configuration without the wrapper: matcher tag 5 (fixes the "tag 4 never sent, cap stuck at 0" side ticket)

**Root cause.**
- Tag 4 (and tag 2 init) must be signed by `lp_pda`, which on real markets is the wrapper's matcher-delegate PDA.
- Only the wrapper can sign for it, and the wrapper signs only tag 0, tag 3 and the fixed 78-byte tag 2 (wrapper tag 83).
- So **no wizard, seed or LP owner can ever send tag 4**. It was unreachable, not merely unsent. Every context's `backing_fee_cap_bps` is 0 and every other parameter is frozen at init.

**Fix (matcher-only, no wrapper change): tag 5 Configure with owner-proof auth.**
- Accounts: `[0] lp_owner (signer)`, `[1] matcher_ctx (writable)`.
- Data: `[5][1][wrapper_program_id 32][market 32][lp_portfolio 32][bump 1][op ...]`.
- The matcher recomputes `create_program_address(["matcher", market, lp_portfolio, lp_owner, matcher_program_id, matcher_ctx, [bump]], wrapper_program_id)` and requires it to equal `ctx.lp_pda`. Otherwise it fails with `Custom(8005)`.
- `[5][0]...` (auth by an `lp_pda` signature) also exists, for direct contexts.

Ops:
- `op 0 [cap u16]` — SetBackingFeeCap (0..=10000).
- `op 1 [SetParams 105 bytes]` — full params, including kind 0/1/2 and the v2 block. See `SetParams::encode`.

**What the wizard/seed must send.** After `InitMatcherCtx` (wrapper tag 83) lands, in the same or a later tx signed by the LP owner:
1. `matcher tag 5, auth 1, op 0, cap = <market backing fee cap bps>`. The wizard currently seeds backing with `tradeFeeCapBps: 10_000`, so send the cap the market's backing fee actually needs. With cap 0, every CPI trade that would charge a non-zero backing-domain fee against the LP fails closed.
2. For v2 pricing: either create the ctx with `kind = 2` in tag 83 (this gets conservative defaults), or send `op 1` with explicit parameters.

This works for **already-deployed contexts** as soon as the matcher program is upgraded to v2 in place. No re-seed is needed.

## 6. Error codes (matcher Custom)

| code | name | meaning |
|---|---|---|
| 8001 | ERR_INCONSISTENT_LEG_ORACLE_PRICE | existing |
| 8002 | ERR_STALE_MARK | mark older than the configured limit (ext `mark_slot`, or the observed-unchanged-price fallback) |
| 8003 | ERR_MARK_SLOT_IN_FUTURE | ext `mark_slot` > Clock.slot |
| 8004 | ERR_ASSET_MISMATCH | a kind-2 or observed-staleness ctx is bound to another asset (one such ctx per asset) |
| 8005 | ERR_OWNER_PROOF_MISMATCH | tag-5 owner proof does not reproduce `ctx.lp_pda` |

The P1 wrapper and SDK error maps should add 8002–8005, attributed to the matcher program ID.

## 7. Kind 2 (Adaptive) pricing

Given a fill `f` (already clipped by `max_fill_abs`, the inventory limit, headroom and the stale-reducing clip):

```
total_bps = clamp( base_spread
                 + adaptive_fee                    # state-only, never size-dependent
                 + cp_impact(f·oracle/1e6)         # ceil(k·n/(D−n)), k = impact_k_bps (10_000 = exact CP), D = liquidity_notional_e6
                 + skew_net(inv_pre → inv_post)    # signed: surcharge − thin-side rebate
                 , 0, max_total )
buy  price = ceil(oracle·(1e4+total)/1e4)    sell price = floor(oracle·(1e4−total)/1e4)
```

- **Size clip, not a price clamp.** `f` is reduced to the largest size whose `base + fee + max(skew,0) + impact ≤ max_total`. The fill carries `FLAG_PARTIAL_OK`. (In kind 1, a large trade gets the clamped price: effectively a free option on size.)
- **Adaptive fee.** `clamp(fee_lo + vol_a_milli/1000·σ + σ²/vol_b_den, fee_lo, fee_hi)`:
  - σ is the EWMA (`vol_alpha_bps`) of the per-`vol_ref_slots` squared relative move of the oracle price handed to the matcher;
  - samples are taken at most once per `vol_ref_slots`, each capped at `vol_move_cap_10bps·10` bps and normalised by `ref/dt`;
  - `fee_cold` is used until `vol_warmup` samples have been taken.
- **Skew.** The cost is `W_s(|end|) − W_s(|start|)` when moving away from 0 and `−(W_r(|start|) − W_r(|end|))` when moving toward 0, with `W(x) = ∫₀ˣ min(mult·t/ref, cap) dt`:
  - surcharge slope is `skew_spread_mult_bps`, rebate slope `thin_rebate_mult_bps ≤ skew`;
  - caps are `skew_cap_bps`, `rebate_cap_bps ≤ skew_cap ≤ 5000`;
  - the reference inventory is `skew_ref_inventory`.

  Consequences:
  - Path-independent: splitting a trade cannot reduce the surcharge.
  - A round trip from flat never nets the taker a rebate.
  - Monotone in size and in skew.
  - The price never crosses the oracle.

  **Note:** in kind 2, `skew_spread_mult_bps` means *bps at |inventory| = skew_ref_inventory*. In kinds 0/1 it keeps its v1 meaning, `|inventory_q|·mult/1e4` in raw q units, capped at 5000.
- **Not split-proof: CP impact.** Impact depends on trade size only, so N small trades pay less impact than one large one. That is true of any per-trade impact. The split-proof defence is the inventory skew.

## 8. V2 block (ctx offsets 178..256; `src/v2.rs::V2Block`)

| ctx off | type | field | notes |
|---|---|---|---|
| 178 | u8 | block_version | 1 = present (0 = v1 ctx) — the wrapper's send-extension marker |
| 179 | u8 | flags | bit0 STALE_ALLOW_REDUCING |
| 180 | u16 | fee_lo_bps | |
| 182 | u16 | fee_hi_bps | ≤ 1000; base + hi ≤ max_total |
| 184 | u16 | fee_cold_bps | lo ≤ cold ≤ hi |
| 186 | u16 | vol_a_milli | |
| 188 | u16 | vol_b_den | 0 = no quadratic term |
| 190 | u16 | vol_alpha_bps | 1..=10000 |
| 192 | u8 | vol_warmup_left | countdown; tag 5 sets it from `vol_warmup` |
| 193 | u8 | vol_move_cap_10bps | ≥ 1 |
| 194 | u16 | vol_ref_slots | ≥ 1 |
| 196 | u16 | thin_rebate_mult_bps | ≤ skew_spread_mult_bps |
| 198 | u16 | skew_cap_bps | ≤ 5000 |
| 200 | u16 | rebate_cap_bps | ≤ skew_cap |
| 202 | u16 | max_mark_age_slots | 0 = off |
| 204 | u16 | observed_stale_slots | 0 = off |
| 206 | u16 | bound_asset_plus1 | state |
| 208 | u64 | skew_ref_inventory | > 0 if skew or rebate on |
| 216 | u64 | vol_var_e4 | state (bps²·1e4) |
| 224 | u64 | vol_last_price_e6 | state |
| 232 | u64 | vol_last_slot | state |
| 240 | u64 | obs_price_e6 | state |
| 248 | u64 | obs_since_slot | state |

For kinds 0/1 a v2 block may carry only `flags`, `max_mark_age_slots`, `observed_stale_slots` and state. Every pricing field must be 0. `MatcherCtx` offsets are relative to byte 64 of the account, so absolute account offset = ctx off + 64.

## 9. SetParams (tag 5 op 1, 105 bytes)

| off | type | field |
|---|---|---|
| 0 | u8 | kind (0/1/2) |
| 1 | u32 | trading_fee_bps (kinds 0/1 pricing; ignored by kind 2) |
| 5 | u32 | base_spread_bps |
| 9 | u32 | max_total_bps |
| 13 | u32 | impact_k_bps (kind 2: 10000 = exact CP; ≤ 100000) |
| 17 | u128 | liquidity_notional_e6 (kind 2: virtual CP depth) |
| 33 | u128 | max_fill_abs (u128::MAX is clamped to i128::MAX) |
| 49 | u128 | max_inventory_abs |
| 65 | u16 | fee_to_insurance_bps |
| 67 | u16 | skew_spread_mult_bps |
| 69 | u8 | enable_v2 (0/1) |
| 70 | u8 | v2 flags |
| 71..97 | u16×… | fee_lo, fee_hi, fee_cold, vol_a_milli, vol_b_den, vol_alpha_bps (u16 each), vol_warmup (u8 @83), vol_move_cap_10bps (u8 @84), vol_ref_slots, thin_rebate_mult_bps, skew_cap_bps, rebate_cap_bps, max_mark_age_slots, observed_stale_slots (u16 each, @85..97) |
| 97 | u64 | skew_ref_inventory |

Preserved across op 1:
- inventory, insurance accrual/remainder, lp_pda, lp_account_id, backing_fee_cap;
- the asset binding and the observed-mark tracker.

The volatility estimator restarts, with the cold fee until warm.

## P1 status (read from `feat/p1-safety-release@3ea438b0`, read-only, 2026-09-29 ~20:40)

P1 already implements this ABI (`risk_limits_v17::encode_matcher_call_ext`):
- It sends `ext_version 1` with `HEADROOM|MARK_SLOT`, `mark_slot = last_good_oracle_slot` and `headroom` saturated to u64.
- It is gated by a per-asset protocol flag, `AssetRiskLimitsV17::matcher_ext_mode` (0 = legacy bytes).
- It clips the request to headroom itself before the CPI. The matcher's headroom clip is then a no-op second line.

`last_good_oracle_slot` is written from `Clock::get().slot` (`authenticated_slot_or_fallback`). That is the same clock the matcher reads, so the comparison is consistent. Keeper hold-republishes also advance it, so the authoritative path does not have the P2-1 false positive.

Requests to P1:
1. Also set `EXEC_BAND` with its effective `exec_band_bps`, so kind-2 quotes clip instead of hitting Custom(66).
2. Set `TAKER_REDUCING` when the leg only reduces the taker's position. Without it, a taker whose close *grows* the LP's inventory is refused under a stale mark.
3. Leave `ACCEPTS_FEE_REQUEST` off until the wrapper accepts return bits 22..31 and routes the fee.
4. Keep `matcher_ext_mode = 0` until the matcher program on that asset is upgraded to v2. The deployed `12bd671` rejects non-zero bytes 43..67.

## 10. Version-2 extension: the LP's real engine position (matcher-inventory-sync, 2026-10-03)

**Why.** `inventory_base` only moves on matcher fills. Every out-of-matcher change of the LP's
engine position leaves it stale: a liquidation or `RebalanceReduce` (tag 44) of an account on the
opposite side ADL-scales the LP's leg, a full drain resets the LP's side to zero, and the LP's own
liquidation, force-close or a no-CPI trade moves it directly. On devnet (wrapper `ETDLAdi…` @
`553d76f0`, matcher `EDKKgRaV…` @ `4a0f696`) 11 of 44 bound contexts had drifted on 2026-10-03.
A stale counter both blocks fills the LP has room for (phantom cap) and admits fills past the
LP's configured cap (upstream `aeyakovenko/percolator-prog#406`). The single scalar also nets
fills across assets (`aeyakovenko/percolator-match#8`).

**Wire.** `ext_version = 2` is 40 bytes: bytes 0..24 are the v1 block (same flags, same
field-without-flag and reserved-byte rules; flags may be 0), bytes 24..40 are `lp_position_q`,
the LP's signed ADL-effective engine position on THIS leg's asset (i128 LE, `i128::MIN` refused).

| call | legacy | v1 | v2 |
|---|---|---|---|
| tag 0 | 67 bytes, ext all-zero | 67 bytes | **exactly 83 bytes** (43 + 40) |
| tag 3 | `18 + 26n` | `18 + 26n + 24n` | `18 + 26n + 40n` (never mixed) |

**Semantics.** Tag 0: `inventory_base := lp_position_q` before pricing, then the fill applies as
before, so the stored counter is re-synchronised by every v2 fill. Tag 3: every leg carries the
PRE-batch position of its asset; leg `i` prices from `lp_position_q - sum(exec_size of earlier
legs on the same asset)`, so legs on different assets never net. Pricing (skew), the inventory
cap and the stale-mark LP-reducing clip all read the real position. Only the wrapper can sign for
`lp_pda`, so the field is authenticated.

**Compatibility.** A v0/v1 call behaves exactly as before (the stale counter). With no drift a
v2 call is byte-identical in its return and stored counter to the v1 call (tests
`inventory_sync.rs::v2_with_accurate_counter_is_identical_to_v1`). The deployed `4a0f696`
rejects version 2 with `InvalidInstructionData`: **upgrade the matcher before the wrapper that
sends v2.** The wrapper sends v2 only to the canonical matcher program; any other matcher keeps
receiving v0/v1.
