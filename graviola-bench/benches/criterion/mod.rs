#[cfg(not(all(feature = "__bench_cycles", target_arch = "aarch64")))]
use std::time::{Duration, Instant};

#[cfg(feature = "__bench_codspeed")]
pub use codspeed_criterion_compat::*;
#[cfg(not(feature = "__bench_codspeed"))]
pub use criterion::*;

#[cfg(all(feature = "__bench_cycles", target_arch = "aarch64"))]
mod aarch64;

// A measurement type for use with Criterion.
// Depending on the features enabled, it wraps either Criterion's
// standard `WallTime` metric or a target-specific measurement.
pub struct CustomMeasurement(
    #[cfg(not(all(feature = "__bench_cycles", target_arch = "aarch64")))] measurement::WallTime,
    #[cfg(all(feature = "__bench_cycles", target_arch = "aarch64"))] aarch64::CycleCount,
);

impl measurement::Measurement for CustomMeasurement {
    #[cfg(not(all(feature = "__bench_cycles", target_arch = "aarch64")))]
    type Intermediate = Instant;

    #[cfg(not(all(feature = "__bench_cycles", target_arch = "aarch64")))]
    type Value = Duration;

    #[cfg(all(feature = "__bench_cycles", target_arch = "aarch64"))]
    type Intermediate = u64;

    #[cfg(all(feature = "__bench_cycles", target_arch = "aarch64"))]
    type Value = u64;

    fn start(&self) -> Self::Intermediate {
        self.0.start()
    }

    fn end(&self, i: Self::Intermediate) -> Self::Value {
        self.0.end(i)
    }

    fn add(&self, v1: &Self::Value, v2: &Self::Value) -> Self::Value {
        self.0.add(v1, v2)
    }

    fn zero(&self) -> Self::Value {
        self.0.zero()
    }

    fn to_f64(&self, value: &Self::Value) -> f64 {
        self.0.to_f64(value)
    }

    fn formatter(&self) -> &dyn measurement::ValueFormatter {
        self.0.formatter()
        //&CustomMeasurementFormatter
    }
}

impl CustomMeasurement {
    #[allow(dead_code)]
    #[cfg(not(all(feature = "__bench_cycles", target_arch = "aarch64")))]
    pub fn new() -> Self {
        CustomMeasurement(measurement::WallTime)
    }

    #[allow(dead_code)]
    #[cfg(all(feature = "__bench_cycles", target_arch = "aarch64"))]
    pub fn new() -> Self {
        CustomMeasurement(aarch64::CycleCount)
    }
}

/*
struct CustomMeasurementFormatter;

impl measurement::ValueFormatter for CustomMeasurementFormatter {
    fn scale_values(&self, _typical_value: f64, _values: &mut [f64]) -> &'static str {
        "cycle"
    }

    fn scale_throughputs(&self, _typical_value: f64, _throughput: &Throughput, _values: &mut [f64]) -> &'static str {
        "elem/sycle"
    }

    fn scale_for_machines(&self, _values: &mut [f64]) -> &'static str {
        "cycle"
    }
}
*/

#[macro_export]
macro_rules! custom_benchmark_group {
    ($name:ident, $( $target:path ),+ $(,)*) => {
        criterion_group!{
            name = $name;
            config = Criterion::default().with_measurement(CustomMeasurement::new());
            targets = $( $target ),+
        }
    }
}
