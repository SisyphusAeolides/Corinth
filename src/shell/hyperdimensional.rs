const D: usize = 1024; // hypervector dimension (use 10000 in prod)

/// A bipolar hypervector in {-1, +1}^D
#[derive(Clone)]
pub struct HyperVector([i8; D]);

impl HyperVector {
    /// Random projection of a byte string to hypervector space
    pub fn encode(input: &[u8]) -> Self {
        let mut v = [0i8; D];
        // Deterministic pseudo-random projection via xorshift seeded by content
        let mut seed = 0xdeadbeef_u64;
        for (i, val) in v.iter_mut().enumerate() {
            // Mix input bytes into dimension i
            for (j, &b) in input.iter().enumerate() {
                seed ^= (b as u64).wrapping_mul(0x9e3779b97f4a7c15);
                seed ^= seed >> 30;
                seed = seed.wrapping_mul(0xbf58476d1ce4e5b9);
                seed ^= (i as u64).wrapping_mul(0x94d049bb133111eb);
            }
            *val = if (seed >> 63) & 1 == 1 { 1 } else { -1 };
        }
        Self(v)
    }

    /// Bundle (superpose) multiple hypervectors — holographic union
    pub fn bundle(vectors: &[Self]) -> Self {
        if vectors.is_empty() { return Self([0i8; D]); }
        let mut sum = [0i32; D];
        for v in vectors {
            for (s, &x) in sum.iter_mut().zip(v.0.iter()) {
                *s += x as i32;
            }
        }
        let mut result = [0i8; D];
        for (r, &s) in result.iter_mut().zip(sum.iter()) {
            *r = if s >= 0 { 1 } else { -1 };
        }
        Self(result)
    }

    /// Bind (XOR-like multiply) two hypervectors — associative memory key
    pub fn bind(&self, other: &Self) -> Self {
        let mut result = [0i8; D];
        for ((r, &a), &b) in result.iter_mut().zip(self.0.iter()).zip(other.0.iter()) {
            *r = a * b; // {-1,+1} multiplication = XOR in bipolar
        }
        Self(result)
    }

    /// Cosine similarity ∈ [-1, 1]
    pub fn similarity(&self, other: &Self) -> f32 {
        let dot: i32 = self.0.iter().zip(other.0.iter()).map(|(&a, &b)| a as i32 * b as i32).sum();
        dot as f32 / D as f32 // both are unit hypervectors by construction
    }
}

/// Holographic command memory — the shell's associative recall engine
pub struct HolographicShell {
    history: alloc::vec::Vec<(HyperVector, alloc::string::String)>,
    context: HyperVector, // rolling context vector — last N commands superposed
}

impl HolographicShell {
    pub fn new() -> Self {
        Self { history: alloc::vec::Vec::new(), context: HyperVector([1i8; D]) }
    }

    /// Record a completed command into holographic memory
    pub fn remember(&mut self, cmd: &str) {
        let hv = HyperVector::encode(cmd.as_bytes());
        // Update rolling context: bind new command to context shift
        let shift_key = HyperVector::encode(b"__temporal_shift__");
        let shifted = self.context.bind(&shift_key);
        self.context = HyperVector::bundle(&[shifted, hv.clone()]);
        self.history.push((hv, alloc::string::String::from(cmd)));
    }

    /// Autocomplete: find history entry most similar to partial input
    pub fn recall(&self, partial: &str) -> Option<&str> {
        let query = HyperVector::encode(partial.as_bytes());
        self.history.iter()
            .max_by(|(a, _), (b, _)| {
                query.similarity(a).partial_cmp(&query.similarity(b)).unwrap()
            })
            .map(|(_, cmd)| cmd.as_str())
    }

    /// Analogy completion: cmd_a is to cmd_b as partial is to ???
    /// Uses hypervector arithmetic: result ≈ encode(partial) * encode(cmd_b) / encode(cmd_a)
    pub fn analogy(&self, cmd_a: &str, cmd_b: &str, partial: &str) -> Option<&str> {
        let a = HyperVector::encode(cmd_a.as_bytes());
        let b = HyperVector::encode(cmd_b.as_bytes());
        let p = HyperVector::encode(partial.as_bytes());
        // HDC analogy: target = p * b * a  (since a * b encodes the relationship)
        let relationship = a.bind(&b);
        let target = p.bind(&relationship);
        self.history.iter()
            .max_by(|(va, _), (vb, _)| {
                target.similarity(va).partial_cmp(&target.similarity(vb)).unwrap()
            })
            .map(|(_, cmd)| cmd.as_str())
    }
}
