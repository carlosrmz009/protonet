use hdrhistogram::Histogram;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

#[derive(Debug, Clone, Default)]
pub struct MetricsSnapshot {
    pub records_sent: u64,
    pub records_received: u64,
    pub duplicates_ignored: u64,
    pub invalid_rejected: u64,
    pub queue_saturations: u64,
    pub validation_p50_us: u64,
    pub validation_p95_us: u64,
    pub validation_p99_us: u64,
    pub persistence_p50_us: u64,
    pub persistence_p95_us: u64,
    pub persistence_p99_us: u64,
    pub propagation_p50_us: u64,
    pub propagation_p95_us: u64,
    pub propagation_p99_us: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub upload_bytes_per_second: u64,
    pub download_bytes_per_second: u64,
    pub process_cpu_percent: f32,
    pub process_memory_bytes: u64,
}

pub struct NetworkMetrics {
    pub records_sent: AtomicU64,
    pub records_received: AtomicU64,
    pub duplicates_ignored: AtomicU64,
    pub invalid_rejected: AtomicU64,
    pub queue_saturations: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    validation: Histogram<u64>,
    persistence: Histogram<u64>,
    propagation: Histogram<u64>,
    started: Instant,
}

impl Default for NetworkMetrics {
    fn default() -> Self {
        Self {
            records_sent: AtomicU64::new(0),
            records_received: AtomicU64::new(0),
            duplicates_ignored: AtomicU64::new(0),
            invalid_rejected: AtomicU64::new(0),
            queue_saturations: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            validation: Histogram::new(3).expect("valid histogram"),
            persistence: Histogram::new(3).expect("valid histogram"),
            propagation: Histogram::new(3).expect("valid histogram"),
            started: Instant::now(),
        }
    }
}

impl NetworkMetrics {
    pub fn record_validation(&mut self, micros: u64) {
        let _ = self.validation.record(micros.max(1));
    }

    pub fn record_persistence(&mut self, micros: u64) {
        let _ = self.persistence.record(micros.max(1));
    }

    pub fn record_propagation(&mut self, micros: u64) {
        let _ = self.propagation.record(micros.max(1));
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        let elapsed = self.started.elapsed().as_secs_f64().max(0.001);
        let bytes_sent = self.bytes_sent.load(Ordering::Relaxed);
        let bytes_received = self.bytes_received.load(Ordering::Relaxed);
        MetricsSnapshot {
            records_sent: self.records_sent.load(Ordering::Relaxed),
            records_received: self.records_received.load(Ordering::Relaxed),
            duplicates_ignored: self.duplicates_ignored.load(Ordering::Relaxed),
            invalid_rejected: self.invalid_rejected.load(Ordering::Relaxed),
            queue_saturations: self.queue_saturations.load(Ordering::Relaxed),
            validation_p50_us: quantile(&self.validation, 0.50),
            validation_p95_us: quantile(&self.validation, 0.95),
            validation_p99_us: quantile(&self.validation, 0.99),
            persistence_p50_us: quantile(&self.persistence, 0.50),
            persistence_p95_us: quantile(&self.persistence, 0.95),
            persistence_p99_us: quantile(&self.persistence, 0.99),
            propagation_p50_us: quantile(&self.propagation, 0.50),
            propagation_p95_us: quantile(&self.propagation, 0.95),
            propagation_p99_us: quantile(&self.propagation, 0.99),
            bytes_sent,
            bytes_received,
            upload_bytes_per_second: (bytes_sent as f64 / elapsed) as u64,
            download_bytes_per_second: (bytes_received as f64 / elapsed) as u64,
            process_cpu_percent: 0.0,
            process_memory_bytes: 0,
        }
    }
}

fn quantile(histogram: &Histogram<u64>, quantile: f64) -> u64 {
    if histogram.is_empty() {
        0
    } else {
        histogram.value_at_quantile(quantile)
    }
}

pub struct ProcessSampler {
    last_cpu_100ns: u64,
    last_sample: Instant,
}

impl Default for ProcessSampler {
    fn default() -> Self {
        Self {
            last_cpu_100ns: process_cpu_100ns(),
            last_sample: Instant::now(),
        }
    }
}

impl ProcessSampler {
    pub fn sample(&mut self) -> (f32, u64) {
        let now = Instant::now();
        let cpu = process_cpu_100ns();
        let cpu_seconds = cpu.saturating_sub(self.last_cpu_100ns) as f64 / 10_000_000.0;
        let wall_seconds = now
            .saturating_duration_since(self.last_sample)
            .as_secs_f64()
            .max(0.001);
        let processors = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1) as f64;
        self.last_cpu_100ns = cpu;
        self.last_sample = now;
        (
            (cpu_seconds / wall_seconds / processors * 100.0).clamp(0.0, 100.0) as f32,
            process_memory_bytes(),
        )
    }
}

#[cfg(windows)]
fn process_cpu_100ns() -> u64 {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    let ok = unsafe {
        GetProcessTimes(
            GetCurrentProcess(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    };
    if ok == 0 {
        return 0;
    }
    filetime_value(kernel).saturating_add(filetime_value(user))
}

#[cfg(windows)]
fn filetime_value(value: windows_sys::Win32::Foundation::FILETIME) -> u64 {
    (u64::from(value.dwHighDateTime) << 32) | u64::from(value.dwLowDateTime)
}

#[cfg(windows)]
fn process_memory_bytes() -> u64 {
    use windows_sys::Win32::System::ProcessStatus::{
        GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    let mut counters = PROCESS_MEMORY_COUNTERS {
        cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        ..unsafe { std::mem::zeroed() }
    };
    let ok = unsafe {
        GetProcessMemoryInfo(
            GetCurrentProcess(),
            &mut counters,
            std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        )
    };
    if ok == 0 {
        0
    } else {
        counters.WorkingSetSize as u64
    }
}

#[cfg(not(windows))]
fn process_cpu_100ns() -> u64 {
    0
}

#[cfg(not(windows))]
fn process_memory_bytes() -> u64 {
    0
}
