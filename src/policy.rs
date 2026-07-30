//! Reproducible-build scheduling score; never a package trust decision.

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BuildEvidence {
    pub reproducible: f64,
    pub source_cached: f64,
    pub dependency_cached: f64,
    pub thermal_pressure: f64,
}

impl BuildEvidence {
    const fn as_array(self) -> [f64; 4] {
        [
            self.reproducible,
            self.source_cached,
            self.dependency_cached,
            self.thermal_pressure,
        ]
    }
}

pub fn build_score(evidence: BuildEvidence) -> f64 {
    let values = evidence.as_array();
    score_impl(&values)
}

#[cfg(feature = "fortran-policy")]
fn score_impl(values: &[f64; 4]) -> f64 {
    unsafe extern "C" {
        fn arach_corinth_build_score(features: *const f64, count: i32) -> f64;
    }
    // SAFETY: the Fortran boundary reads four contiguous f64 values.
    unsafe { arach_corinth_build_score(values.as_ptr(), values.len() as i32) }
}

#[cfg(not(feature = "fortran-policy"))]
fn score_impl(values: &[f64; 4]) -> f64 {
    let reproducible = values[0].clamp(0.0, 1.0);
    let source = values[1].clamp(0.0, 1.0);
    let dependency = values[2].clamp(0.0, 1.0);
    let thermal = values[3].clamp(0.0, 1.0);
    (reproducible * 0.50 + source * 0.20 + dependency * 0.20 - thermal * 0.20).clamp(0.0, 1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reproducible_cached_build_outranks_unlocked_work() {
        let reproducible = build_score(BuildEvidence {
            reproducible: 1.0,
            source_cached: 1.0,
            dependency_cached: 1.0,
            thermal_pressure: 0.0,
        });
        let unlocked = build_score(BuildEvidence {
            reproducible: 0.0,
            source_cached: 1.0,
            dependency_cached: 1.0,
            thermal_pressure: 0.0,
        });
        assert!(reproducible > unlocked);
    }
}
