//! Small deterministic RNG (xorshift64* seeded through splitmix64). No external crates.

#[derive(Clone, Debug)]
pub struct Rng(u64);

fn splitmix64(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        let s = splitmix64(seed);
        Rng(if s == 0 { 0x2545_F491_4F6C_DD1D } else { s })
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform in [0, 1).
    pub fn uniform(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 * (1.0 / (1u64 << 53) as f64)
    }

    /// Uniform in (0, 1] (safe for ln).
    fn uniform_pos(&mut self) -> f64 {
        1.0 - self.uniform()
    }

    pub fn coin(&mut self) -> bool {
        self.next_u64() >> 63 == 1
    }

    /// Standard normal (Box-Muller).
    pub fn normal(&mut self) -> f64 {
        let u1 = self.uniform_pos();
        let u2 = self.uniform();
        (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
    }

    /// Exponential with the given rate (mean 1/rate).
    pub fn exp(&mut self, rate: f64) -> f64 {
        -self.uniform_pos().ln() / rate
    }
}

/// Stable seed from a string label (FNV-1a) so every param set sees identical flow.
pub fn seed_from(label: &str, salt: u64) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325 ^ salt;
    for b in label.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let mut a = Rng::new(7);
        let mut b = Rng::new(7);
        for _ in 0..1000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn moments() {
        let mut r = Rng::new(42);
        let n = 200_000;
        let (mut s, mut s2, mut u, mut e, mut heads) = (0.0, 0.0, 0.0, 0.0, 0u32);
        for _ in 0..n {
            let z = r.normal();
            s += z;
            s2 += z * z;
            u += r.uniform();
            e += r.exp(2.0);
            heads += r.coin() as u32;
        }
        let n = n as f64;
        assert!((s / n).abs() < 0.01, "normal mean {}", s / n);
        assert!((s2 / n - 1.0).abs() < 0.02, "normal var {}", s2 / n);
        assert!((u / n - 0.5).abs() < 0.005);
        assert!((e / n - 0.5).abs() < 0.005, "exp mean {}", e / n);
        assert!((heads as f64 / n - 0.5).abs() < 0.005);
    }
}
