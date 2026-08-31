# Performance measurements

Measured 2026-08-30 on a local WSL2 Ubuntu 24.04 x86-64 runner using the
stripped, thin-LTO release binary built with Rust 1.88.0. These are observations
from that environment, not universal guarantees.

| Measurement | Result | Target | Status |
|---|---:|---:|---|
| Release binary | 16,652,552 bytes (15.88 MiB) | < 50 MiB | met |
| Idle RSS | 10,944 KiB | < 80 MiB | met |
| Startup to healthy, 12 samples | p50 6.31 ms; p99 6.52 ms | < 1 s | met |
| Local chat path, 600 keep-alive requests | p50 0.436 ms; p99 0.690 ms | informative | measured |
| Direct no-op baseline | p50 0.334 ms; p99 0.564 ms | informative | measured |
| Local added latency | p50 0.102 ms; p99 0.127 ms | p50 < 2 ms; p99 < 10 ms | met |
| Plan 16 routes, Criterion 95% interval | 117.19-118.77 microseconds | informative | measured |
| Live 2026-07-28 capability discovery and config pin | 57.62 ms | informative | measured |
| Two-source deterministic demo, 20 processes | p50 3.79 ms; p99 4.20 ms | informative | measured |
| 512 list requests at concurrency 32 | 512 HTTP 200; p99 34.45 ms | bounded | met |

The added-latency value subtracts independently measured distribution
quantiles, so the small p99 delta should not be read as paired-sample precision.
The end-to-end GaugeMesh p99 is the more conservative number.

Queue, process, and cleanup bounds are also executable tests: each tenant has a
finite semaphore and queue, the global in-flight limit is 256, tenant tracking
is capped at 1,024, two references to a shareable process consume one process
slot, restart attempts are capped at two, and cancellation tests assert that
owned listeners and transports close. No external control plane was used.

macOS and native Windows resource measurements were not run locally. CI covers
functional builds on those platforms; this file makes no cross-platform
performance claim.
