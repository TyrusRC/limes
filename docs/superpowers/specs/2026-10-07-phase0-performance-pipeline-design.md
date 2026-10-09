# Phase 0: performance, stability, default pipeline, scan identity

Status: design approved in brainstorming 2026-10-07; this spec awaits review.
Parent: `2026-10-07-asm-platform-roadmap-design.md`.

## Problem

Scans get stuck, the UI drifts from what the workers are doing, the dashboard is slow, and the worker setup ignores the host's CPU and RAM. Audit of the current code found these root causes:

| # | Root cause | Location |
|---|---|---|
| R1 | Tasks block on child tasks with `.get()` inside a worker slot; with parents and children on the same queue, all slots can wait on children that never get a slot | `limes/tasks.py:1474` (port_scan → nmap group), `:1926` (fetch_url chord) |
| R2 | No task time limits and no subprocess timeouts; a hung tool holds its slot forever | `tasks.py:4085`, `:4134` |
| R3 | 21 Celery workers backgrounded in one container followed by `wait`; a dead worker is never restarted and its queue stops | `celery-entrypoint.sh:201-267` |
| R4 | No `acks_late`, no recovery: a worker death mid-task loses the task, `report` never runs, scan stays "running" | `limes/settings.py:199-208` |
| R5 | Hardcoded concurrency (`--autoscale=80,10` prefork + ~400 gevent slots) regardless of host; leads to OOM, which feeds R3/R4 | `celery-entrypoint.sh:225`, `.env` |
| R6 | No DB connection pooling; hundreds of concurrent tasks against Postgres' default 100 connections | `settings.py:62` |
| R7 | `stream_command` rewrites the whole growing `Command.output` on every output line (quadratic DB load) | `tasks.py:4170` |
| R8 | Container start runs `makemigrations` in production, apt/pip installs, git clones and downloads | `celery-entrypoint.sh:3-194` |
| R9 | Concurrent tasks read-modify-write the whole `ScanHistory`/`SubScan` row to append celery ids (lost updates) | `celery_custom_task.py:192-199` |
| R10 | Every task start/end enqueues a notification task even when notifications are off | `celery_custom_task.py:220-234` |
| R11 | Dashboard runs ~30 separate COUNT queries through 2-3 joins, uncached; `CACHES` is per-process LocMem | `dashboard/views.py:39-100`, `settings.py:340` |
| R12 | Production serves Django with `manage.py runserver` (single-process dev server); three containers run `migrate` concurrently at start | `web/entrypoint.sh`, `beat-entrypoint.sh` |
| R13 | Overlapping tools (5 crawlers, 6 subdomain tools, dalfox/crlfuzz/wafw00f duplicating assay) waste CPU, RAM and image size | `tasks.py`, `Dockerfile`, entrypoint |
| S1 | Commands built as strings and run with `shell=True` with target-derived values interpolated (command injection) | many call sites in `tasks.py` |
| S2 | `ollama` publishes 11434 on all interfaces without auth | `docker-compose.yml:143-151` |
| S3 | `.env` with credentials is tracked in git (upstream defaults, publicly known) | `.env` |

## Scope

In: R1-R13, S1-S3, the default pipeline, scan identity (headers + User-Agent), and measured before/after benchmarks.

Out (later sub-projects): the asset inventory and data-model replacement, scope tiers beyond "subdomains of a target root", ASN/CIDR/WHOIS expansion, graph, continuous scheduling, UI redesign, scoring. Phase 0 keeps the current models (`Domain`, `ScanHistory`, `Subdomain`, `EndPoint`, `Vulnerability`) and current screens.

Because the scope gate does not exist until sub-project 2, phase 0 runs amass in domain-enumeration mode only (no ASN/CIDR/WHOIS expansion), so discovery cannot pull in third-party assets.

## Design

### 1. Services and queues

The 21 queues collapse to three. Each queue is served by its own compose service built from the same image:

| Service | Queue | Pool and flags | Tasks |
|---|---|---|---|
| `worker-scan` | `scan` | prefork, `--prefetch-multiplier=1`, `-O fair`, `--max-tasks-per-child=20` | every task that runs an external tool |
| `worker-io` | `io` | gevent | result parsing into the DB, whois, geo, notifications, dashboard stats |
| `worker-orch` | `orchestrate` | prefork, concurrency 2 | `initiate_scan`, `initiate_subscan`, stage transitions, `report`, reaper |
| `beat` | — | — | schedules (unchanged scheduler) |
| `web` | — | gunicorn (`gthread`, workers from sizing) | Django |
| `migrate` | — | one-shot | `migrate`, `collectstatic`, fixture load; other services `depends_on: condition: service_completed_successfully` |
| `pgbouncer` | — | transaction pooling | between all Django processes and Postgres |

Every long-running service: `restart: unless-stopped`, a healthcheck (`celery -A limes inspect ping -d celery@$HOSTNAME` for workers, an HTTP `/healthz` for web), and a `mem_limit` from sizing.

Task routing is declared once in settings (`CELERY_TASK_ROUTES`) instead of per-decorator `queue=` arguments.

### 2. Resource sizing

`web/limes/sizing.py`, run by each service's entrypoint, reads the container's real limits: cgroup v2 `cpu.max` and `memory.max`, falling back to `os.cpu_count()` and `/proc/meminfo`. It prints shell exports:

- `SCAN_SLOTS = clamp(min(cpus, (mem - reserve) // per_slot_mem), 1, 32)`, with `per_slot_mem = 1.5 GiB` (assay may launch headless Chrome) and `reserve = 1 GiB`.
- `IO_CONCURRENCY = min(50, pool_size)`.
- `WEB_WORKERS = clamp(2 * cpus + 1, 2, 9)`.

Environment overrides (`SCAN_SLOTS`, `IO_CONCURRENCY`, `WEB_WORKERS`) win when set. `MAX_CONCURRENCY` / `MIN_CONCURRENCY` are removed.

Runtime: a custom autoscaler (`worker_autoscaler = limes.autoscale:MemoryAwareAutoscaler`, a subclass of `celery.worker.autoscale.Autoscaler`) grows `worker-scan` only while memory use is below 80% and 1-minute load is below the CPU count, and shrinks when memory use exceeds 90%. Bounds: `--autoscale=SCAN_SLOTS,1`.

NOTE in code: sizing uses fixed per-slot estimates; the upgrade path is per-tool measured RSS.

### 3. Scan flow correctness

- **No joins inside tasks (R1).** `port_scan` no longer waits on an nmap `group`; nmap service detection runs inside the same task over the open ports, one nmap invocation per batch of hosts. `fetch_url` runs its crawler commands as a chord with the cleanup/merge as the callback; nothing calls `.get()` inside a task. A test asserts no task module contains `allow_join_result`.
- **Time limits (R2).** Every task has `soft_time_limit` and `time_limit` from the profile (defaults: discovery 2 h, port scan 2 h, crawl 2 h, DAST 6 h, parsing 15 min). The command runner passes `timeout=` to the subprocess, kills the process group on expiry, and records the timeout.
- **Acknowledgement and recovery (R4).** `task_acks_late = True`, `task_reject_on_worker_lost = True`, `worker_prefetch_multiplier = 1`, Redis `visibility_timeout` above the longest `time_limit` (7 h). Tool tasks are idempotent: each writes to its own output path and DB writes are upserts.
- **Reaper.** A beat task every 5 minutes on `orchestrate`: scans in `RUNNING` whose tasks have no live Celery state and no activity heartbeat for longer than the stage's `time_limit` plus a grace period are marked failed with a reason, and `report` runs for them.
- **Atomic updates (R9).** Appending celery ids and status changes use single-statement updates (`ArrayField` append via `Func`/`F()` in `update()`), never load-modify-`save()` of the whole row.
- **Notifications (R10).** `LimesTask.notify` enqueues only when notification settings are enabled, and only on terminal state changes.

### 4. Command runner (R7, S1)

One runner in `limes/commands.py` replaces `run_command` and `stream_command`:

- Takes an argument list only; `shell=True` is not available. Shell pipelines (`cat | sort -u`, `grep`) are replaced with Python file operations.
- Starts the tool in its own process group with `timeout`.
- Streams stdout to the tool's output file on disk; the `Command` row stores the command (redacted), return code, duration and the last 64 KiB of output, written once at the end and at most every 5 seconds while running (no per-line writes).
- Redaction: argument values matching configured secret header names, and any value passed through the secret-file mechanism, are replaced with `***` before logging, storing, or writing `commands.txt`.

Target-derived strings (hostnames, URLs) are validated at intake (hostname/URL syntax) and passed only as separate arguments.

### 5. Default pipeline (R13)

Replaces the tool-selection logic in `tasks.py` with fixed stages; profiles (`quick`, `normal`, `thorough`, `passive`) set depth, limits and timeouts:

1. Discovery: amass v5 (`amass enum -d <root>` in domain mode, results read with `amass subs -names -d <root>` from its asset DB) + subfinder; results merged and deduplicated.
2. Resolve: dnsx with wildcard filtering.
3. Ports: naabu; nmap `-sV` only on open ports.
4. HTTP probe: httpx with title, status, tech, TLS, and screenshots (replaces EyeWitness).
5. Crawl: katana (`-jc`, scope locked per host with `-fs fqdn`) + gau; JS, source maps and exposed `.git` content saved under the scan's results directory.
6. DAST: assay as a subprocess with `--json`, profile mapped from the scan profile, destructive flags never passed, crawl URLs as targets. Findings map to `Vulnerability` (severity, confidence, CWE, OWASP, CVSS, `verified`, evidence, remediation).
7. Code audit: `mantis.audit(dir, packs=["secrets", "web"])` on stage 5 artifacts, SAST only. Findings map to `Vulnerability` with source `mantis`.

Removed from tasks, Dockerfile and entrypoint: sublist3r, oneforall, ctfr, tlsx-as-discovery, gospider, hakrawler, waybackurls, EyeWitness, Firefox/geckodriver, the standalone nuclei task (nuclei stays installed because assay uses it), dalfox, crlfuzz, wafw00f, GooFuzz. theHarvester, h8mail, dorking and ffuf are disabled in the default pipeline (code kept behind a disabled stage until their sub-project decides).

Existing scan engine YAML is mapped to the nearest profile by a data migration; unknown keys are ignored and logged.

### 6. Image and startup (R8, R12)

- All tool installs, Python requirements, wordlists, nuclei templates and `whatportis` data move into the Dockerfile with pinned versions. Entrypoints contain no `apt`, `pip`, `git clone`, `wget` or `makemigrations`.
- Migrations are committed to the repo; the `migrate` one-shot applies them.
- `web` runs gunicorn; nginx serves static files.
- Template and tool updates become an explicit admin action, not a startup side effect.

### 7. Data layer (R6, R11)

- pgbouncer (transaction mode) in front of Postgres; Django connects through it with `CONN_MAX_AGE = 0` and server-side cursors disabled. Postgres `max_connections` and pgbouncer `default_pool_size` come from sizing.
- `CACHES` uses Redis (separate DB index from the broker).
- Dashboard counts become one aggregate query per model using conditional `Count(..., filter=Q(...))`, cached in Redis for 60 s per project and invalidated when a scan finishes.
- Indexes added for the dashboard and list filters: `Subdomain(target_domain, scan_history)`, `Subdomain(http_status)`, `EndPoint(scan_history, http_status)`, `Vulnerability(scan_history, severity)`, `ScanActivity(scan_of, status)`, plus date fields used in the 7-day trends.
- Redis: `maxmemory` with `noeviction`, `result_expires = 1 day`.

### 8. Scan identity (headers + User-Agent)

- Project-level identity (User-Agent + headers), per-target override via the existing `Domain.request_headers`. Each header has `secret: bool`.
- Secret values are encrypted at rest with a key from `LIMES_SECRET_KEY_ENCRYPTION` (Fernet from `cryptography`).
- Applied to httpx (explicit `User-Agent`, `-random-agent` disabled), katana, and assay (written into assay's `--config` YAML: `user_agent`, `headers`). Secrets reach tools only through 0600 temp files under the scan's results dir, deleted when the task ends (including on failure).
- Full coverage of assay traffic paths (headless, raw sockets, nuclei UA) depends on the separate assay `RequestIdentity` change; until it lands, the UI states which assay detectors may not carry the identity.

### 9. Security fixes (S2, S3)

- `ollama` gets no published port; it is reachable only on the internal network.
- `.env` is removed from the index (`git rm --cached`), `.env` is added to `.gitignore`, and `.env.example` ships placeholders. The installer generates random values for every password and key. Release notes state that deployments that used the upstream defaults must rotate them.

## Testing and evidence

Bug fixes start with a failing test that reproduces the bug:

- R1: a test that runs the scan chain with `CELERY_TASK_ALWAYS_EAGER=False` against a 1-slot worker and asserts the chain completes (fails today by hanging, guarded by a test timeout); plus a static test that no task module uses `allow_join_result`.
- R2: runner test with a command that sleeps past its timeout; asserts the process group is killed and the result is a timeout.
- R4/reaper: a scan with a task killed mid-run is marked failed by the reaper within the grace period.
- R7: runner test asserting the number of DB writes for a 10,000-line command is bounded (≤ duration/5 s + 2), not per line.
- R9: concurrent appends from N threads all land.
- S1: the runner rejects strings; a hostname containing `;`, `$()` or backticks is rejected at intake and never reaches a shell.
- Redaction: a secret header value never appears in `Command`, `commands.txt` or logs.
- Sizing: unit tests over fake cgroup files (limits set, `max`, missing files).
- Pipeline mapping: assay and mantis JSON samples map to the expected `Vulnerability` fields; destructive assay flags never appear in the built argument list.

Benchmark (recorded before any change and after phase 0, results committed under `docs/benchmarks/`):

- Dashboard and target detail page: p50/p95 response time and query count on a seeded dataset (1 project, 50 targets, 200k subdomains, 1M endpoints, 50k vulnerabilities).
- Scan status lag: time from task state change to the value shown by the scan status API.
- Stuck scans: 20 concurrent scans of a local test target (lab hosts only, never third parties); count of scans not finished within their time budget.
- Peak RSS per service and total, and image size.

Phase 0 is done when every test above passes, the benchmark shows zero stuck scans in the concurrent run, and the dashboard p95 is under 500 ms on the seeded dataset.

## Risks

- amass v5 output and asset-DB layout differ from v3; the integration reads them through `amass subs` and is pinned to a tested version.
- Removing tools changes results for existing users; the profile mapping and release notes list what replaced each tool.
- acks_late re-runs a task after a worker crash; tool tasks must stay idempotent (upserts, per-task output paths).
