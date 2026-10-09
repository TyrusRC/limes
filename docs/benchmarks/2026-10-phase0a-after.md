# Phase 0A after-benchmark

Commit: `d5dfa719` (baseline: [2026-10-phase0-baseline.md](2026-10-phase0-baseline.md))

Host: 10 CPUs

```
               total        used        free      shared  buff/cache   available
Mem:              19           4           2           0          13          15
Swap:              0           0           0
```

## Dashboard (raw)

```
| mode | p50 ms | p95 ms | queries |
|---|---|---|---|
| cold | 460 | 504 | 77 |
| warm | 40 | 42 | 56 |
```

## Concurrent scans (raw)

```
scans=20 {'failed': 20} stuck=0
```

## Memory (raw)

```
limes-labtarget-1 8.883MiB / 19.52GiB
limes-proxy-1 9.867MiB / 19.52GiB
limes-web-1 726.5MiB / 2GiB
limes-worker-orch-1 275.8MiB / 1GiB
limes-worker-scan-1 173.1MiB / 8GiB
limes-worker-io-1 168.4MiB / 2GiB
limes-beat-1 150.2MiB / 512MiB
limes-pgbouncer-1 8.59MiB / 19.52GiB
limes-redis-1 10.84MiB / 19.52GiB
limes-db-1 185.6MiB / 19.52GiB
limes-ollama-1 19.24MiB / 19.52GiB
limes-test-redis-1 14.8MiB / 19.52GiB
limes-test-db-1 33.24MiB / 19.52GiB
```

## Image (raw)

```
docker.pkg.github.com/yogeshojha/limes/limes:latest   5e211b8a58cb       5.62GB         1.18GB        
limes-celery-beat:latest                                6284284fec58       5.62GB         1.18GB        
limes-celery:latest                                     8434101194ad       5.62GB         1.18GB        
limes-certs:latest                                      f96158f998b7       22.8MB         6.69MB        
limes-next:local                                        6f6dd3a3bb43       6.78GB         1.51GB   U    
limes-test-test:latest                                  e5bc4ef48e2f       5.62GB         1.18GB        
```

## Before / after

| metric | baseline | after |
|---|---|---|
| dashboard cold p50 / p95 ms | 1807 / 1838 | 460 / 504 |
| dashboard warm p50 / p95 ms | 1803 / 1811 | 40 / 42 |
| queries cold / warm | 161 / 160 | 77 / 56 |
| 20 scans | failed 20, stuck=0 | failed 20, stuck=0 |
| app image size | 5.62GB (x3 images) | 6.78GB (single limes-next:local) |

Note: scans still all fail fast (the baseline's http_crawl failure on the lab alias host was not in 0A scope), so the deadlock hang was never reproduced either before or after; "no scan left RUNNING/INITIATED" is the signal used.

## Exit criteria (amended)

- (a) static no-join test: PASS (`test_no_allow_join_result ... ok`, 1 test OK)
- (b) bench-scans stuck=0: PASS (`scans=20 {'failed': 20} stuck=0`)
- (c) dashboard warm p95 < 500 ms AND cold queries <= 25: FAIL. Warm p95 = 42 ms (pass), but cold queries = 77 (limit 25).
- (d) `make test`: PASS (Ran 61 tests, OK)
- (e) `makemigrations --check --dry-run`: PASS (No changes detected)
