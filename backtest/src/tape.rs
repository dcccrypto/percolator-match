//! Price tapes: loading, BURNIE 1m -> 1s upsampling (linear / Brownian bridge), and the
//! largest-10-minute-move window used for the keeper OUTAGE scenario.

use crate::rng::Rng;
use std::path::Path;

#[derive(Clone, Debug)]
pub struct Tape {
    pub token: String,
    /// calm / volatile / 3d-linear / 3d-bridge
    pub day: String,
    /// One price per second (USD, f64).
    pub prices: Vec<f64>,
    /// In-sample for the V2 parameter search.
    pub in_sample: bool,
}

impl Tape {
    pub fn label(&self) -> String {
        format!("{}_{}", self.token, self.day)
    }
}

pub fn load_csv(path: &Path) -> Result<Vec<f64>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if i == 0 {
            if line.trim() != "ts_ms,price" {
                return Err(format!("{}: unexpected header {line:?}", path.display()));
            }
            continue;
        }
        if line.trim().is_empty() {
            continue;
        }
        let (_, p) = line
            .split_once(',')
            .ok_or_else(|| format!("{}:{}: bad row", path.display(), i + 1))?;
        let p: f64 = p
            .trim()
            .parse()
            .map_err(|e| format!("{}:{}: {e}", path.display(), i + 1))?;
        if !(p.is_finite() && p > 0.0) {
            return Err(format!("{}:{}: bad price {p}", path.display(), i + 1));
        }
        out.push(p);
    }
    if out.is_empty() {
        return Err(format!("{}: empty", path.display()));
    }
    Ok(out)
}

/// Linear interpolation of minute closes to 1 s (value of row m sits at t = 60 m).
pub fn upsample_linear(minutes: &[f64]) -> Vec<f64> {
    let mut out = Vec::with_capacity(minutes.len() * 60);
    for w in minutes.windows(2) {
        for k in 0..60 {
            out.push(w[0] + (w[1] - w[0]) * k as f64 / 60.0);
        }
    }
    out.push(*minutes.last().unwrap());
    out
}

/// Brownian-bridge fill between minute closes (log space). Per-second vol = trailing
/// 60-minute realized vol of 1-minute log returns / sqrt(60). Endpoints are exact.
pub fn upsample_bridge(minutes: &[f64], seed: u64) -> Vec<f64> {
    let mut rng = Rng::new(seed);
    let rets: Vec<f64> = minutes.windows(2).map(|w| (w[1] / w[0]).ln()).collect();
    let mut out = Vec::with_capacity(minutes.len() * 60);
    for (m, w) in minutes.windows(2).enumerate() {
        let lo = m.saturating_sub(60);
        let win = &rets[lo..=m];
        let n = win.len() as f64;
        let mean = win.iter().sum::<f64>() / n;
        let var = win.iter().map(|r| (r - mean) * (r - mean)).sum::<f64>() / n;
        let sig_s = var.sqrt() / 60f64.sqrt();
        let (a, b) = (w[0].ln(), w[1].ln());
        let mut x = a;
        out.push(w[0]);
        for k in 1..60 {
            // Bridge step from x at (k-1) to target b at 60.
            let rem = (60 - k + 1) as f64;
            let drift = (b - x) / rem;
            let sd = sig_s * ((rem - 1.0) / rem).sqrt();
            x += drift + sd * rng.normal();
            out.push(x.exp());
        }
    }
    out.push(*minutes.last().unwrap());
    out
}

/// Start second of the `len`-second window with the largest |P(t+len)/P(t) - 1|.
pub fn largest_move_window(prices: &[f64], len: usize) -> usize {
    let mut best = (0usize, -1.0f64);
    if prices.len() <= len {
        return 0;
    }
    for t in 0..prices.len() - len {
        let m = (prices[t + len] / prices[t] - 1.0).abs();
        if m > best.1 {
            best = (t, m);
        }
    }
    best.0
}

pub fn load_all(data_dir: &Path, bridge_seed: u64) -> Result<Vec<Tape>, String> {
    let mut tapes = Vec::new();
    let bin = [
        ("SOL", "calm", "SOL_calm_20260815.csv", true),
        ("SOL", "volatile", "SOL_volatile_20260822.csv", true),
        ("JUP", "calm", "JUP_calm_20260817.csv", true),
        ("JUP", "volatile", "JUP_volatile_20260906.csv", true),
        ("TRUMP", "calm", "TRUMP_calm_20260721.csv", false),
        ("TRUMP", "volatile", "TRUMP_volatile_20260822.csv", false),
        ("PENGU", "calm", "PENGU_calm_20260807.csv", false),
        ("PENGU", "volatile", "PENGU_volatile_20260823.csv", false),
    ];
    for (tok, day, f, ins) in bin {
        let prices = load_csv(&data_dir.join(f))?;
        if prices.len() != 86_400 {
            return Err(format!("{f}: expected 86400 rows, got {}", prices.len()));
        }
        tapes.push(Tape {
            token: tok.into(),
            day: day.into(),
            prices,
            in_sample: ins,
        });
    }
    let bm = load_csv(&data_dir.join("BURNIE_1m_20260926T1845_20260929T1826.csv"))?;
    tapes.push(Tape {
        token: "BURNIE".into(),
        day: "3d-linear".into(),
        prices: upsample_linear(&bm),
        in_sample: false,
    });
    tapes.push(Tape {
        token: "BURNIE".into(),
        day: "3d-bridge".into(),
        prices: upsample_bridge(&bm, bridge_seed),
        in_sample: false,
    });
    Ok(tapes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linear_endpoints() {
        let v = upsample_linear(&[1.0, 2.0, 2.0]);
        assert_eq!(v.len(), 121);
        assert_eq!(v[0], 1.0);
        assert_eq!(v[60], 2.0);
        assert!((v[30] - 1.5).abs() < 1e-12);
        assert_eq!(v[120], 2.0);
    }

    #[test]
    fn bridge_hits_closes() {
        let m = [1.0, 1.1, 0.9, 1.0];
        let v = upsample_bridge(&m, 3);
        for (i, c) in m.iter().enumerate() {
            assert!((v[i * 60] - c).abs() < 1e-12);
        }
    }

    #[test]
    fn window() {
        let mut p = vec![1.0; 2000];
        for x in p.iter_mut().skip(1000) {
            *x = 2.0;
        }
        let s = largest_move_window(&p, 600);
        assert!((400..1000).contains(&s));
    }
}
