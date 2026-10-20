#!/usr/bin/env python3
"""v22kani MS (2026-10-20): width-free composition step for matcher pricing (gap G3).

NOT Kani. z3 over unbounded Int. The premises are exactly what the full-width Kani harnesses
`ms_m1n_passive_exec_bounds_structural` / `ms_m2n_vamm_exec_bounds_structural`
(src/kani_v22_gaps_ms.rs) assert on the REAL `compute_execution_units`, plus the language fact
that `u128::checked_mul(o, b)` returns `Some(o*b)` exactly when it does not overflow:
  ask: x = o*b, 1e4+bf <= b <= 1e4+m, x <= 1e4*p <= x+9999
  bid: x = o*b, 1e4-m <= b <= 1e4-bf, 1e4*p <= x <= 1e4*p+9999, p >= 1
with 0 <= bf <= m <= 9000 (validate()). The goals are the audit's K-M1/M2/M4/M5 price assertions
verbatim. Per lemma: premises SAT, premises AND NOT goal UNSAT, controls SAT.
"""
import sys
from z3 import Ints, Solver, And, Not, sat, unsat

bad = 0
def check(name, prem, goal, expect):
    global bad
    s = Solver(); s.set("timeout", 600_000)
    s.add(prem)
    if goal is not None:
        s.add(Not(goal))
    r = s.check()
    ok = r == expect
    bad += 0 if ok else 1
    extra = (" model=" + str(s.model()).replace("\n", "")) if r == sat else ""
    print(f"{name}: {r} (expected {expect}) {'OK' if ok else 'UNEXPECTED'}{extra}", flush=True)

o, m, bf, b, x, p = Ints("o m bf b x p")
D = 10_000
cfg = And(o >= 0, o <= 2**64 - 1, m >= 0, m <= 9000, bf >= 0, bf <= m)

ask = And(cfg, x == o * b, b >= D + bf, b <= D + m, D * p >= x, D * p <= x + D - 1)
check("ASK premises", ask, None, sat)
check("ASK p >= o", ask, p >= o, unsat)
check("ASK p*1e4 <= o*(1e4+m) + 9999", ask, D * p <= o * (D + m) + D - 1, unsat)
check("ASK tight control (at the cap: p*1e4 + 1e4 > o*(1e4+m) reachable)", And(ask, m > bf, o > 0),
      D * p + D <= o * (D + m), sat)
check("ASK mutant control (ceil + 1)",
      And(cfg, x == o * b, b >= D + bf, b <= D + m, D * (p - 1) >= x, D * (p - 1) <= x + D - 1),
      D * p <= o * (D + m) + D - 1, sat)

bid = And(cfg, x == o * b, b >= D - m, b <= D - bf, D * p <= x, D * p + D - 1 >= x, p >= 1)
check("BID premises", bid, None, sat)
check("BID p <= o", bid, p <= o, unsat)
check("BID p*1e4 + 9999 >= o*(1e4-m)", bid, D * p + D - 1 >= o * (D - m), unsat)
check("BID tight control (strictly below the oracle reachable)", bid, p >= o, sat)
check("BID mutant control (floor - 1)",
      And(cfg, x == o * b, b >= D - m, b <= D - bf, D * (p + 1) <= x, D * (p + 1) + D - 1 >= x, p >= 1),
      D * p + D - 1 >= o * (D - m), sat)

print("RESULT:", "ALL AS EXPECTED" if bad == 0 else f"{bad} UNEXPECTED")
sys.exit(1 if bad else 0)
