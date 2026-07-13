use criterion::Throughput;
use criterion::measurement::{Measurement, ValueFormatter};
use std::arch::asm;

// Measurement plug-in for Criterion that measures elapsed CPU cycles
// by reading the ARM counter-timer hardware register.

pub struct CycleCount;

impl Measurement for CycleCount {
    type Intermediate = u64;
    type Value = u64;

    fn start(&self) -> Self::Intermediate {
        self.get_current()
    }

    fn end(&self, i: Self::Intermediate) -> Self::Value {
        self.get_current() - i
    }

    fn add(&self, v1: &Self::Value, v2: &Self::Value) -> Self::Value {
        v1 + v2
    }

    fn zero(&self) -> Self::Value {
        0
    }

    fn to_f64(&self, value: &Self::Value) -> f64 {
        *value as _
    }

    fn formatter(&self) -> &dyn ValueFormatter {
        &CycleCountFormatter
    }
}

impl CycleCount {
    fn get_current(&self) -> u64 {
        let mut value = 0;
        unsafe {
            asm!(
                "isb",
                "mrs {destination}, CNTVCT_EL0",
                "isb",
                destination = inout(reg) value,
            )
        }
        value
    }
}

struct CycleCountFormatter;

impl ValueFormatter for CycleCountFormatter {
    fn scale_values(&self, _typical_value: f64, _values: &mut [f64]) -> &'static str {
        "cycle"
    }

    fn scale_throughputs(
        &self,
        _typical_value: f64,
        _throughput: &Throughput,
        _values: &mut [f64],
    ) -> &'static str {
        "elem/cycle"
    }

    fn scale_for_machines(&self, _values: &mut [f64]) -> &'static str {
        "cycle"
    }
}
