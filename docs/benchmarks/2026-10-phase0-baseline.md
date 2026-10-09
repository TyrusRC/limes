# Phase 0 baseline (before fixes)

Commit: `e551a17c` (unmodified application code; benchmark tooling only)

Host: 10 CPUs

```
               total        used        free      shared  buff/cache   available
Mem:              19           6           1           0          11          12
Swap:              0           0           0
```

## Dashboard

Seeded with defaults: 50 domains x 4000 subs, 20000 endpoints, 1000 vulns each. Max queries is per request.

| mode | p50 ms | p95 ms | queries |
|---|---|---|---|
| cold | 1807 | 1838 | 161 |
| warm | 1803 | 1811 | 160 |

## Concurrent scans

```
scans=20 {'failed': 20} stuck=0
```

All 20 scans ended as `failed` (none stuck) well inside the budget. Celery log shows each scan failing in `http_crawl`, verbatim:

```
initiate_scan | INFO | IP lab.limes.test is not a valid IP. Skipping.
initiate_scan | ERROR | 'NoneType' object has no attribute 'address'
  File "/usr/src/app/limes/tasks.py", line 3024, in http_crawl
    fields={'IPs': f'• `{ip.address}`'},
AttributeError: 'NoneType' object has no attribute 'address'
initiate_scan | ERROR | string indices must be integers   (ScanHistory.error_message)
```

So the stuck-scan (R1) reproduction was not obtained on this lab target: the scans fail early on a separate bug (httpx result for a lab alias host has no resolvable IP). This is recorded unfixed, as the baseline.

## Memory

```
limes-labtarget-1 8.824MiB / 19.52GiB
limes-proxy-1 12.88MiB / 19.52GiB
limes-web-1 204.1MiB / 19.52GiB
limes-celery-beat-1 164.1MiB / 19.52GiB
limes-celery-1 4.478GiB / 19.52GiB
limes-redis-1 20.31MiB / 19.52GiB
limes-db-1 204.3MiB / 19.52GiB
ollama 20.02MiB / 19.52GiB
limes-test-redis-1 14.99MiB / 19.52GiB
limes-test-db-1 29.98MiB / 19.52GiB
```

## Image

```
docker.pkg.github.com/yogeshojha/limes/limes:latest 5.62GB
limes-celery:latest 5.62GB
limes-celery-beat:latest 5.62GB
limes-certs:latest 22.8MB
limes-test-test:latest 5.62GB
```
