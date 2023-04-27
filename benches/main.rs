mod dwarf;
mod gsym;
mod normalize;

use std::time::Duration;

use criterion::criterion_group;
use criterion::criterion_main;
use criterion::Criterion;
use criterion_perf_events::Perf;

use perfcnt::linux::HardwareEventType as Hardware;
use perfcnt::linux::PerfCounterBuilderLinux as Builder;


fn benchmark(c: &mut Criterion<Perf>) {
    let mut group = c.benchmark_group("main");
    group.sample_size(500);
    group.warm_up_time(Duration::from_secs(5));
    group.confidence_level(0.98);
    group.significance_level(0.02);
    dwarf::benchmark(&mut group);
    gsym::benchmark(&mut group);
    normalize::benchmark(&mut group);
}

criterion_group!(
    name = benches;
    config = Criterion::default().with_measurement(Perf::new(Builder::from_hardware_event(Hardware::Instructions)));
    targets = benchmark
);
criterion_main!(benches);
