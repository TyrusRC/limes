# Phase 0A: Stabilize the Platform — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop scans from getting stuck, keep the UI in sync with the workers, size workers to the host, and make the dashboard fast — without changing which scan tools run.

**Architecture:** Three Celery queues (`scan`, `io`, `orchestrate`), each served by its own restartable compose service sized from cgroup limits, with a memory-aware autoscaler. One Django-free command runner (argument lists, timeouts, process-group kill, bounded DB writes, redaction) replaces the per-line-saving runners. In-task `.get()` joins are removed, every task gets time limits, `acks_late`, and a reaper fails scans that stop making progress. Dashboard numbers come from aggregate queries cached in Redis; Postgres sits behind pgbouncer; Django runs under gunicorn.

**Tech Stack:** Python 3.10, Django 3.2, Celery 5.4 (Redis broker), PostgreSQL 12 + pgbouncer, gunicorn, django-redis, psycogreen, Docker Compose.

**Spec:** `docs/superpowers/specs/2026-10-07-phase0-performance-pipeline-design.md` (this plan implements R1–R12, S2, S3 and the benchmarks; R13, S1 completion and scan identity are plan 0B).

## Global Constraints

- Python files under `web/limes/tasks.py`, `web/limes/common_func.py`, `web/limes/celery_custom_task.py` are indented with TABS; keep tabs there. New files use 4 spaces.
- Time limits (spec): discovery 2 h, port scan 2 h, crawl 2 h, DAST 6 h, parsing 15 min. Soft limit = hard − 120 s.
- Redis `visibility_timeout` must exceed the longest `time_limit` (6 h): use 7 h (25200 s).
- Sizing: `per_slot_mem = 1.5 GiB`, `reserve = 1 GiB`, `SCAN_SLOTS = clamp(min(cpus, (mem − reserve) // per_slot_mem), 1, 32)`, `IO_CONCURRENCY = min(50, DB_POOL_SIZE)`, `WEB_WORKERS = clamp(2·cpus + 1, 2, 9)`; env vars of the same name override.
- Autoscaler: grow only while memory use < 80 % and 1-min load < CPU count; shrink above 90 % memory.
- Command records: store at most the last 64 KiB of output; write while running at most every 5 s.
- No scanning of third-party hosts in tests or benchmarks: only the compose `labtarget` service.
- Commit identity for this repo is already configured (TyrusRC). No AI attribution lines in commits.
- New tests live in `web/tests/core/` and run with `make test`. Never run `web/tests/test_scan.py` (it scans real internet targets).

## Review Focus

1. **A worker killed by OOM mid-task** (acks_late redelivers it): the task re-runs and must not duplicate rows or crash on existing output files — Task 8 adds a test that `LimesTask` output writing tolerates an existing file.
2. **A tool that ignores SIGTERM and spawns children** (e.g. a crawler launching Chrome): the soft time limit must still kill the whole process group — Task 5 tests a child process surviving the parent.
3. **Dashboard for a project with zero scans**: aggregates return `None`, not 0 — Task 10 tests the empty project renders with zeros.
4. **cgroup v1 hosts or missing cgroup files** (older Docker, WSL): sizing must fall back to `os.cpu_count()` / `/proc/meminfo` instead of crashing the entrypoint — Task 3 tests missing files.
5. **A scan stuck in INITIATED** because `initiate_scan` crashed before setting RUNNING: the reaper must catch it too — Task 9 tests an INITIATED scan.

---

## File Structure

| File | Responsibility |
|---|---|
| `docker-compose.test.yml` (create) | db + redis + `test` service for running Django tests |
| `Makefile` (modify) | `test`, `bench-*`, updated `SERVICES` |
| `web/tests/core/__init__.py` (create) | test package for this plan |
| `web/dashboard/management/commands/seed_benchmark.py` (create) | bulk-seed a benchmark project |
| `web/dashboard/management/commands/bench_dashboard.py` (create) | measure dashboard latency + query count |
| `web/startScan/management/commands/bench_scans.py` (create) | launch N concurrent scans of the lab target and report stuck ones |
| `docker-compose.bench.yml` (create) | `labtarget` nginx service |
| `docs/benchmarks/2026-10-phase0-baseline.md`, `...-after.md` (create) | recorded results |
| `web/limes/sizing.py` (create) | read cgroup/proc limits, compute pool sizes, print exports (stdlib only) |
| `web/limes/autoscale.py` (create) | `decide()` + `MemoryAwareAutoscaler` |
| `web/limes/commands.py` (create) | Django-free runner: `stream()`, `run()`, `redact()`, `display()` |
| `web/limes/command_log.py` (create) | `DbCommandRecorder` (Django glue for `Command` rows) |
| `web/limes/fsutil.py` (create) | `safe_rmtree()`, `clear_dir()` under allowed roots |
| `web/limes/urlfiles.py` (create) | `merge_url_files()` replacing `cat | sort -u | grep -v` |
| `web/limes/db_ops.py` (create) | `append_celery_id()` atomic array append |
| `web/limes/celery_routing.py` (create) | `TASK_PLAN`, routes, annotations, `MAX_TIME_LIMIT` |
| `web/limes/reaper.py` (create) | `find_stuck_scans()`, `reap_stuck_scans` task |
| `web/limes/health.py` (create) | `/healthz` view |
| `web/dashboard/stats.py` (create) | `project_stats()`, `invalidate()` |
| `web/startScan/migrations/0003_phase0_indexes.py` (create) | concurrent index creation |
| `web/limes/tasks.py`, `celery_custom_task.py`, `celery.py`, `settings.py`, `urls.py` (modify) | wiring |
| `web/dashboard/views.py`, `web/startScan/views.py`, `web/scanEngine/views.py`, `web/api/views.py`, `web/api/shared_api_tasks.py`, `web/startScan/models.py` (modify) | wiring |
| `web/Dockerfile`, `web/requirements.txt`, `web/entrypoint.sh`, `web/celery-entrypoint.sh`, `web/beat-entrypoint.sh`, `web/migrate-entrypoint.sh` (create) | image + startup |
| `docker-compose.yml`, `docker-compose.dev.yml` (rewrite) | services, healthchecks, limits |
| `.env.example`, `.gitignore`, `scripts/gen_env.py`, `scripts/test_gen_env.py`, `install.sh` (modify/create) | secrets + host-sized defaults |

---

### Task 1: Test harness

**Files:**
- Create: `docker-compose.test.yml`, `web/tests/core/__init__.py`, `web/tests/core/test_harness.py`
- Modify: `Makefile`

**Interfaces:**
- Produces: `make test` (runs `python3 manage.py test tests.core`), `make manage ARGS="..."` (runs any manage.py command in the test container).

- [ ] **Step 1: Create the test compose file**

`docker-compose.test.yml`:
```yaml
services:
  db:
    image: "postgres:12.3-alpine"
    environment:
      - POSTGRES_DB=${POSTGRES_DB}
      - POSTGRES_USER=${POSTGRES_USER}
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
  redis:
    image: "redis:7.2-alpine"
  test:
    build:
      context: ./web
    entrypoint: []
    working_dir: /usr/src/app
    volumes:
      - ./web:/usr/src/app
    env_file: .env
    environment:
      - DEBUG=0
      - CELERY_BROKER=redis://redis:6379/0
      - CACHE_URL=redis://redis:6379/1
      - POSTGRES_HOST=db
      - POSTGRES_PORT=5432
    depends_on:
      - db
      - redis
```

- [ ] **Step 2: Add Makefile targets** (append after the `rm:` target)

```makefile
TEST_COMPOSE := ${DOCKER_COMPOSE} -p limes-test -f docker-compose.test.yml

test:			## Run phase-0 test suite in containers.
	${TEST_COMPOSE} run --rm test python3 manage.py test tests.core -v 2

manage:			## Run a manage.py command in the test container: make manage ARGS="..."
	${TEST_COMPOSE} run --rm test python3 manage.py ${ARGS}

test-down:		## Remove test containers and volumes.
	${TEST_COMPOSE} down -v
```
Add `test manage test-down` to the `.PHONY` line.

- [ ] **Step 3: Write a smoke test**

`web/tests/core/__init__.py`: empty file.

`web/tests/core/test_harness.py`:
```python
from django.db import connection
from django.test import SimpleTestCase, TestCase


class HarnessTest(TestCase):
    def test_database_is_postgres(self):
        self.assertEqual(connection.vendor, 'postgresql')


class ImportTest(SimpleTestCase):
    def test_tasks_module_imports(self):
        import limes.tasks  # noqa: F401
```

- [ ] **Step 4: Run it**

Run: `make test`
Expected: image builds (first run is slow), 2 tests, `OK`.

- [ ] **Step 5: Commit**

```bash
git add docker-compose.test.yml Makefile web/tests/core/
git commit -m "test: add containerized test harness for phase 0 work"
```

---

### Task 2: Baseline benchmark

**Files:**
- Create: `web/dashboard/management/__init__.py`, `web/dashboard/management/commands/__init__.py`, `web/dashboard/management/commands/seed_benchmark.py`, `web/dashboard/management/commands/bench_dashboard.py`, `web/startScan/management/__init__.py`, `web/startScan/management/commands/__init__.py`, `web/startScan/management/commands/bench_scans.py`, `docker-compose.bench.yml`, `docs/benchmarks/2026-10-phase0-baseline.md`
- Modify: `Makefile`

**Interfaces:**
- Produces: `manage.py seed_benchmark [--domains 50 --subs 4000 --endpoints 20000 --vulns 1000]`, `manage.py bench_dashboard [--runs 30]` (prints a markdown table), `manage.py bench_scans [--scans 20 --budget-min 45]` (prints counts by final status). Reused unchanged by Task 13.

- [ ] **Step 1: Seed command**

`web/dashboard/management/commands/seed_benchmark.py`:
```python
import random
from datetime import timedelta

from django.core.management.base import BaseCommand
from django.utils import timezone

from dashboard.models import Project
from scanEngine.models import EngineType
from startScan.models import EndPoint, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain

BATCH = 5000


class Command(BaseCommand):
    help = 'Bulk-seed a "bench" project for dashboard benchmarks (lab data only).'

    def add_arguments(self, parser):
        parser.add_argument('--domains', type=int, default=50)
        parser.add_argument('--subs', type=int, default=4000)
        parser.add_argument('--endpoints', type=int, default=20000)
        parser.add_argument('--vulns', type=int, default=1000)

    def handle(self, *args, **opts):
        now = timezone.now()
        project, _ = Project.objects.get_or_create(slug='bench', defaults={'name': 'bench', 'insert_date': now})
        engine, _ = EngineType.objects.get_or_create(engine_name='bench-seed', defaults={'yaml_configuration': 'http_crawl: {}'})
        rnd = random.Random(42)
        for d in range(opts['domains']):
            domain, _ = Domain.objects.get_or_create(
                name=f'seed{d}.bench.test', defaults={'project': project, 'insert_date': now})
            scan = ScanHistory.objects.create(
                domain=domain, scan_type=engine, start_scan_date=now, scan_status=2)
            subs = [Subdomain(name=f's{i}.{domain.name}', scan_history=scan, target_domain=domain,
                              http_status=rnd.choice([0, 200, 301, 403, 404]),
                              discovered_date=now - timedelta(days=rnd.randint(0, 13)))
                    for i in range(opts['subs'])]
            Subdomain.objects.bulk_create(subs, batch_size=BATCH)
            sub_ids = list(Subdomain.objects.filter(scan_history=scan).values_list('id', flat=True))
            eps = [EndPoint(http_url=f'https://s{i % opts["subs"]}.{domain.name}/p{i}', scan_history=scan,
                            target_domain=domain, subdomain_id=sub_ids[i % len(sub_ids)],
                            http_status=rnd.choice([200, 302, 404, 500]),
                            discovered_date=now - timedelta(days=rnd.randint(0, 13)))
                   for i in range(opts['endpoints'])]
            EndPoint.objects.bulk_create(eps, batch_size=BATCH)
            vulns = [Vulnerability(name=f'bench-vuln-{i % 40}', severity=rnd.choice([-1, 0, 1, 2, 3, 4]),
                                   scan_history=scan, target_domain=domain,
                                   subdomain_id=sub_ids[i % len(sub_ids)],
                                   discovered_date=now - timedelta(days=rnd.randint(0, 13)))
                     for i in range(opts['vulns'])]
            Vulnerability.objects.bulk_create(vulns, batch_size=BATCH)
            self.stdout.write(f'seeded {domain.name}')
```

- [ ] **Step 2: Dashboard benchmark command**

`web/dashboard/management/commands/bench_dashboard.py`:
```python
import statistics
import time

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.management.base import BaseCommand
from django.db import connection
from django.test import Client
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from rolepermissions.roles import assign_role


class Command(BaseCommand):
    help = 'Measure dashboard latency and query count for the "bench" project.'

    def add_arguments(self, parser):
        parser.add_argument('--runs', type=int, default=30)

    def _measure(self, client, url, runs, cold):
        times, queries = [], []
        for _ in range(runs):
            if cold:
                cache.clear()
            with CaptureQueriesContext(connection) as ctx:
                start = time.perf_counter()
                resp = client.get(url)
                times.append((time.perf_counter() - start) * 1000)
            assert resp.status_code == 200, resp.status_code
            queries.append(len(ctx.captured_queries))
        times.sort()
        p95 = times[max(0, int(len(times) * 0.95) - 1)]
        return statistics.median(times), p95, max(queries)

    def handle(self, *args, **opts):
        user, _ = get_user_model().objects.get_or_create(username='bench', defaults={'is_superuser': True, 'is_staff': True})
        assign_role(user, 'sys_admin')
        client = Client()
        client.force_login(user)
        url = reverse('dashboardIndex', kwargs={'slug': 'bench'})
        self.stdout.write('| mode | p50 ms | p95 ms | queries |\n|---|---|---|---|')
        for mode, cold in (('cold', True), ('warm', False)):
            p50, p95, q = self._measure(client, url, opts['runs'], cold)
            self.stdout.write(f'| {mode} | {p50:.0f} | {p95:.0f} | {q} |')
```
(`sys_admin` is the `SysAdmin` role from `web/limes/roles.py`.)

- [ ] **Step 3: Lab target and scan benchmark**

`docker-compose.bench.yml`:
```yaml
services:
  labtarget:
    image: nginx:1.27-alpine
    networks:
      limes_network:
        aliases:
          - lab.limes.test
networks:
  limes_network:
```

`web/startScan/management/commands/bench_scans.py`:
```python
import time

from django.core.management.base import BaseCommand
from django.utils import timezone

from dashboard.models import Project
from limes.common_func import create_scan_object
from limes.definitions import LIVE_SCAN
from limes.tasks import initiate_scan
from scanEngine.models import EngineType
from startScan.models import ScanHistory
from targetApp.models import Domain

LAB_HOST = 'lab.limes.test'
ENGINE_YAML = """
port_scan: {'ports': ['80'], 'rate_limit': 50, 'enable_nmap': true}
http_crawl: {}
fetch_url: {'uses_tools': ['katana', 'gau'], 'remove_duplicate_endpoints': true}
"""
STATUS_NAMES = {-1: 'initiated', 0: 'failed', 1: 'running', 2: 'success', 3: 'aborted'}


class Command(BaseCommand):
    help = 'Start N concurrent scans of the lab target and report scans that never finish.'

    def add_arguments(self, parser):
        parser.add_argument('--scans', type=int, default=20)
        parser.add_argument('--budget-min', type=int, default=45)

    def handle(self, *args, **opts):
        now = timezone.now()
        project, _ = Project.objects.get_or_create(slug='bench', defaults={'name': 'bench', 'insert_date': now})
        domain, _ = Domain.objects.get_or_create(name=LAB_HOST, defaults={'project': project, 'insert_date': now})
        engine, _ = EngineType.objects.update_or_create(engine_name='bench-lab', defaults={'yaml_configuration': ENGINE_YAML})
        ids = []
        for _ in range(opts['scans']):
            scan_id = create_scan_object(host_id=domain.id, engine_id=engine.id)
            initiate_scan.apply_async(kwargs={
                'scan_history_id': scan_id, 'domain_id': domain.id, 'engine_id': engine.id,
                'scan_type': LIVE_SCAN, 'results_dir': '/usr/src/scan_results'})
            ids.append(scan_id)
        deadline = time.monotonic() + opts['budget_min'] * 60
        while time.monotonic() < deadline:
            open_count = ScanHistory.objects.filter(id__in=ids, scan_status__in=[-1, 1]).count()
            if open_count == 0:
                break
            time.sleep(30)
        counts = {}
        for status in ScanHistory.objects.filter(id__in=ids).values_list('scan_status', flat=True):
            counts[STATUS_NAMES.get(status, status)] = counts.get(STATUS_NAMES.get(status, status), 0) + 1
        stuck = counts.get('initiated', 0) + counts.get('running', 0)
        self.stdout.write(f'scans={len(ids)} {counts} stuck={stuck}')
```

Makefile (append):
```makefile
BENCH_COMPOSE := ${DOCKER_COMPOSE} -f docker-compose.yml -f docker-compose.bench.yml

bench-seed:		## Seed benchmark data into the running stack.
	${BENCH_COMPOSE} exec web python3 manage.py seed_benchmark

bench-dashboard:	## Measure dashboard latency on the running stack.
	${BENCH_COMPOSE} exec web python3 manage.py bench_dashboard

bench-scans:		## Run concurrent lab scans on the running stack.
	${BENCH_COMPOSE} up -d labtarget
	${BENCH_COMPOSE} exec web python3 manage.py bench_scans
```
Add them to `.PHONY`.

- [ ] **Step 4: Record the baseline on the current code**

Run, in order:
```bash
make certs && make up            # current stack, current code
make bench-seed
make bench-dashboard > /tmp/dash.txt
make bench-scans > /tmp/scans.txt
docker stats --no-stream --format '{{.Name}} {{.MemUsage}}' > /tmp/mem.txt
docker image ls --format '{{.Repository}}:{{.Tag}} {{.Size}}' | grep -i limes > /tmp/img.txt
```
Write `docs/benchmarks/2026-10-phase0-baseline.md` with the commit hash (`git rev-parse --short HEAD`), host CPU/RAM (`nproc`, `free -g`), and the four outputs verbatim under headings "Dashboard", "Concurrent scans", "Memory", "Image".
Expected: dashboard p95 well above 500 ms; some scans stuck (this is the R1 reproduction).

- [ ] **Step 5: Commit**

```bash
git add docker-compose.bench.yml Makefile web/dashboard/management web/startScan/management docs/benchmarks/2026-10-phase0-baseline.md
git commit -m "test: add benchmark tooling and record phase 0 baseline"
```

---

### Task 3: Resource sizing

**Files:**
- Create: `web/limes/sizing.py`, `web/tests/core/test_sizing.py`

**Interfaces:**
- Produces: `read_cpu_limit(cgroup_root='/sys/fs/cgroup') -> float`, `read_mem_limit(cgroup_root=..., meminfo='/proc/meminfo') -> int` (bytes), `memory_usage_ratio(cgroup_root=..., meminfo=...) -> float` (0..1), `compute(cpus: float, mem_bytes: int, env: Mapping[str, str]) -> dict[str, int]` with keys `SCAN_SLOTS`, `IO_CONCURRENCY`, `WEB_WORKERS`. Running `python3 limes/sizing.py` prints `export KEY=VALUE` lines. Stdlib only (it runs before Django).

- [ ] **Step 1: Write the failing tests**

`web/tests/core/test_sizing.py`:
```python
import os
import tempfile

from django.test import SimpleTestCase

from limes import sizing

GIB = 1024 ** 3
MEMINFO = 'MemTotal:       16384000 kB\nMemFree:  1000 kB\nMemAvailable:    8192000 kB\n'


def make_tree(files):
    root = tempfile.mkdtemp()
    for name, content in files.items():
        with open(os.path.join(root, name), 'w') as f:
            f.write(content)
    return root


class ReadLimitsTest(SimpleTestCase):
    def setUp(self):
        self.meminfo = os.path.join(make_tree({'meminfo': MEMINFO}), 'meminfo')

    def test_cpu_quota(self):
        root = make_tree({'cpu.max': '200000 100000\n'})
        self.assertEqual(sizing.read_cpu_limit(root), 2.0)

    def test_cpu_max_falls_back_to_cpu_count(self):
        root = make_tree({'cpu.max': 'max 100000\n'})
        self.assertEqual(sizing.read_cpu_limit(root), float(os.cpu_count()))

    def test_missing_cgroup_files_fall_back(self):
        root = make_tree({})
        self.assertEqual(sizing.read_cpu_limit(root), float(os.cpu_count()))
        self.assertEqual(sizing.read_mem_limit(root, self.meminfo), 16384000 * 1024)

    def test_memory_limit_capped_by_host_total(self):
        root = make_tree({'memory.max': str(64 * GIB)})
        self.assertEqual(sizing.read_mem_limit(root, self.meminfo), 16384000 * 1024)
        root = make_tree({'memory.max': str(4 * GIB)})
        self.assertEqual(sizing.read_mem_limit(root, self.meminfo), 4 * GIB)

    def test_usage_ratio_excludes_inactive_file_cache(self):
        root = make_tree({'memory.max': str(4 * GIB), 'memory.current': str(3 * GIB),
                          'memory.stat': f'anon 1\ninactive_file {1 * GIB}\n'})
        self.assertAlmostEqual(sizing.memory_usage_ratio(root, self.meminfo), 0.5)

    def test_usage_ratio_without_cgroup_uses_meminfo(self):
        root = make_tree({})
        self.assertAlmostEqual(sizing.memory_usage_ratio(root, self.meminfo), 0.5)


class ComputeTest(SimpleTestCase):
    def test_small_host(self):
        out = sizing.compute(2, 4 * GIB, {})
        self.assertEqual(out, {'SCAN_SLOTS': 2, 'IO_CONCURRENCY': 40, 'WEB_WORKERS': 5})

    def test_memory_bound(self):
        self.assertEqual(sizing.compute(16, 4 * GIB, {})['SCAN_SLOTS'], 2)

    def test_tiny_host_gets_one_slot(self):
        out = sizing.compute(0.5, 1 * GIB, {})
        self.assertEqual(out['SCAN_SLOTS'], 1)
        self.assertEqual(out['WEB_WORKERS'], 2)

    def test_caps(self):
        out = sizing.compute(64, 512 * GIB, {})
        self.assertEqual(out['SCAN_SLOTS'], 32)
        self.assertEqual(out['WEB_WORKERS'], 9)

    def test_env_overrides(self):
        out = sizing.compute(2, 4 * GIB, {'SCAN_SLOTS': '7', 'IO_CONCURRENCY': '', 'DB_POOL_SIZE': '20'})
        self.assertEqual(out['SCAN_SLOTS'], 7)
        self.assertEqual(out['IO_CONCURRENCY'], 20)
```

- [ ] **Step 2: Run to see it fail**

Run: `make test`
Expected: `ImportError: cannot import name 'sizing'`.

- [ ] **Step 3: Implement**

`web/limes/sizing.py`:
```python
"""Size worker pools from the container's real CPU and memory limits (stdlib only)."""
import os
import sys

GIB = 1024 ** 3
PER_SLOT_MEM = int(1.5 * GIB)
RESERVE_MEM = 1 * GIB
CGROUP_ROOT = '/sys/fs/cgroup'
MEMINFO = '/proc/meminfo'


def _read(path):
    with open(path) as f:
        return f.read().strip()


def _meminfo(path):
    values = {}
    with open(path) as f:
        for line in f:
            key, rest = line.split(':', 1)
            values[key] = int(rest.split()[0]) * 1024
    return values


def read_cpu_limit(cgroup_root=CGROUP_ROOT):
    try:
        quota, period = _read(os.path.join(cgroup_root, 'cpu.max')).split()
        if quota != 'max':
            return max(0.1, int(quota) / int(period))
    except (OSError, ValueError):
        pass
    return float(os.cpu_count() or 1)


def read_mem_limit(cgroup_root=CGROUP_ROOT, meminfo=MEMINFO):
    total = _meminfo(meminfo)['MemTotal']
    try:
        raw = _read(os.path.join(cgroup_root, 'memory.max'))
        if raw != 'max':
            return min(int(raw), total)
    except (OSError, ValueError):
        pass
    return total


def memory_usage_ratio(cgroup_root=CGROUP_ROOT, meminfo=MEMINFO):
    try:
        current = int(_read(os.path.join(cgroup_root, 'memory.current')))
        inactive = 0
        for line in _read(os.path.join(cgroup_root, 'memory.stat')).splitlines():
            key, value = line.split()
            if key == 'inactive_file':
                inactive = int(value)
        return max(0, current - inactive) / read_mem_limit(cgroup_root, meminfo)
    except (OSError, ValueError):
        info = _meminfo(meminfo)
        return (info['MemTotal'] - info['MemAvailable']) / info['MemTotal']


def compute(cpus, mem_bytes, env):
    def pick(name, value):
        return int(env[name]) if env.get(name) else value

    slots_by_mem = max(0, mem_bytes - RESERVE_MEM) // PER_SLOT_MEM
    scan_slots = max(1, min(int(cpus), int(slots_by_mem), 32))
    db_pool = int(env.get('DB_POOL_SIZE') or 40)
    web_workers = max(2, min(9, 2 * int(cpus) + 1))
    return {
        'SCAN_SLOTS': pick('SCAN_SLOTS', scan_slots),
        'IO_CONCURRENCY': pick('IO_CONCURRENCY', min(50, db_pool)),
        'WEB_WORKERS': pick('WEB_WORKERS', web_workers),
    }


def main():
    sizes = compute(read_cpu_limit(), read_mem_limit(), os.environ)
    for key, value in sizes.items():
        sys.stdout.write(f'export {key}={value}\n')


if __name__ == '__main__':
    main()
```
Add the NOTE at the top of `compute`: `# NOTE: fixed per-slot memory estimate; upgrade path is measured per-tool RSS.`

- [ ] **Step 4: Run tests**

Run: `make test`
Expected: all sizing tests PASS.

- [ ] **Step 5: Commit**

```bash
git add web/limes/sizing.py web/tests/core/test_sizing.py
git commit -m "feat: size worker pools from container cgroup limits"
```

---

### Task 4: Memory-aware autoscaler

**Files:**
- Create: `web/limes/autoscale.py`, `web/tests/core/test_autoscale.py`

**Interfaces:**
- Consumes: `sizing.memory_usage_ratio()`, `sizing.read_cpu_limit()`.
- Produces: `decide(qty, procs, min_c, max_c, mem_ratio, load, cpus) -> int` (positive = grow by n, negative = shrink by n); `MemoryAwareAutoscaler` (referenced by `CELERY_WORKER_AUTOSCALER = 'limes.autoscale:MemoryAwareAutoscaler'` in Task 8).

- [ ] **Step 1: Write the failing tests**

`web/tests/core/test_autoscale.py`:
```python
from django.test import SimpleTestCase

from limes.autoscale import decide


class DecideTest(SimpleTestCase):
    def test_grows_to_queue_length_when_healthy(self):
        self.assertEqual(decide(qty=5, procs=2, min_c=1, max_c=8, mem_ratio=0.5, load=1, cpus=8), 3)

    def test_grow_capped_by_max(self):
        self.assertEqual(decide(qty=50, procs=2, min_c=1, max_c=8, mem_ratio=0.5, load=1, cpus=8), 6)

    def test_no_growth_under_memory_pressure(self):
        self.assertEqual(decide(qty=5, procs=2, min_c=1, max_c=8, mem_ratio=0.85, load=1, cpus=8), 0)

    def test_no_growth_when_cpu_saturated(self):
        self.assertEqual(decide(qty=5, procs=2, min_c=1, max_c=8, mem_ratio=0.5, load=8.5, cpus=8), 0)

    def test_shrinks_one_when_memory_critical(self):
        self.assertEqual(decide(qty=5, procs=4, min_c=1, max_c=8, mem_ratio=0.95, load=1, cpus=8), -1)

    def test_never_below_min(self):
        self.assertEqual(decide(qty=0, procs=1, min_c=1, max_c=8, mem_ratio=0.95, load=1, cpus=8), 0)

    def test_shrinks_idle_workers(self):
        self.assertEqual(decide(qty=0, procs=4, min_c=1, max_c=8, mem_ratio=0.5, load=1, cpus=8), -3)
```

- [ ] **Step 2: Run to see it fail**

Run: `make test` → `ImportError` for `limes.autoscale`.

- [ ] **Step 3: Implement**

`web/limes/autoscale.py`:
```python
"""Celery autoscaler that refuses to grow under memory or CPU pressure."""
import os

from celery.worker.autoscale import Autoscaler

from limes import sizing

GROW_BELOW_MEM = 0.80
SHRINK_ABOVE_MEM = 0.90


def decide(qty, procs, min_c, max_c, mem_ratio, load, cpus):
    if mem_ratio >= SHRINK_ABOVE_MEM and procs > min_c:
        return -1
    target = max(min(qty, max_c), min_c)
    if target > procs:
        if mem_ratio >= GROW_BELOW_MEM or load >= cpus:
            return 0
        return target - procs
    if target < procs:
        return target - procs
    return 0


class MemoryAwareAutoscaler(Autoscaler):
    def _maybe_scale(self, req=None):
        delta = decide(
            qty=self.qty,
            procs=self.processes,
            min_c=self.min_concurrency,
            max_c=self.max_concurrency,
            mem_ratio=sizing.memory_usage_ratio(),
            load=os.getloadavg()[0],
            cpus=sizing.read_cpu_limit(),
        )
        if delta > 0:
            self.scale_up(delta)
            return True
        if delta < 0:
            self.scale_down(-delta)
            return True
        return False
```

- [ ] **Step 4: Run tests** — `make test`, all PASS.

- [ ] **Step 5: Commit**

```bash
git add web/limes/autoscale.py web/tests/core/test_autoscale.py
git commit -m "feat: add memory-aware Celery autoscaler"
```

---

### Task 5: Command runner

**Files:**
- Create: `web/limes/commands.py`, `web/limes/command_log.py`, `web/limes/fsutil.py`, `web/tests/core/test_commands.py`, `web/tests/core/test_fsutil.py`
- Modify: `web/limes/tasks.py` (`run_command` ≈ line 4053, `stream_command` ≈ line 4118), `web/startScan/views.py:483,765,966`, `web/scanEngine/views.py:583-584`, `web/api/views.py:1321-1322`

**Interfaces:**
- Produces (in `limes.commands`): `ShellCommandError(TypeError)`; `CommandResult(return_code: int | None, timed_out: bool, output_tail: str, output: str, duration: float)`; `redact(text: str, secrets: Iterable[str]) -> str`; `display(argv: list[str], secrets=()) -> str`; `stream(argv, *, timeout=None, cwd=None, output_path=None, secrets=(), recorder=None, flush_interval=5.0, clock=time.monotonic) -> Iterator[str]`; `run(argv, *, capture=True, **same) -> CommandResult`. A recorder has `update(output_tail: str)` and `finish(result: CommandResult)`.
- Produces (in `limes.command_log`): `DbCommandRecorder(command_obj)`.
- Produces (in `limes.fsutil`): `safe_rmtree(path, roots=None)`, `clear_dir(root, roots=None)`.
- `tasks.run_command(...)` and `tasks.stream_command(...)` keep their signatures and gain `timeout=None`.

- [ ] **Step 1: Write failing runner tests**

`web/tests/core/test_commands.py`:
```python
import os
import sys
import tempfile
import time

from django.test import SimpleTestCase

from limes import commands

PY = sys.executable


class Recorder:
    def __init__(self):
        self.updates = 0
        self.result = None

    def update(self, output_tail):
        self.updates += 1

    def finish(self, result):
        self.result = result


class RunnerTest(SimpleTestCase):
    def test_rejects_strings(self):
        with self.assertRaises(commands.ShellCommandError):
            commands.run('echo hi')

    def test_rejects_non_string_items(self):
        with self.assertRaises(commands.ShellCommandError):
            commands.run(['echo', 1])

    def test_metacharacters_are_literal_arguments(self):
        result = commands.run(['echo', 'a; touch /tmp/pwned_by_test $(id)'])
        self.assertEqual(result.output.strip(), 'a; touch /tmp/pwned_by_test $(id)')
        self.assertFalse(os.path.exists('/tmp/pwned_by_test'))

    def test_timeout_kills_process_group_including_children(self):
        marker = tempfile.mktemp()
        script = (f"import subprocess,sys,time;"
                  f"subprocess.Popen([sys.executable,'-c','import time;time.sleep(3);open(\"{marker}\",\"w\")']);"
                  f"time.sleep(30)")
        start = time.monotonic()
        result = commands.run([PY, '-c', script], timeout=1)
        self.assertTrue(result.timed_out)
        self.assertIsNone(result.return_code)
        self.assertLess(time.monotonic() - start, 10)
        time.sleep(4)
        self.assertFalse(os.path.exists(marker), 'child survived the group kill')

    def test_abandoned_stream_kills_process(self):
        marker = tempfile.mktemp()
        script = f"import time;print('go', flush=True);time.sleep(2);open('{marker}','w')"
        stream = commands.stream([PY, '-c', script])
        next(stream)
        stream.close()  # what happens when SoftTimeLimitExceeded is raised while iterating
        time.sleep(3)
        self.assertFalse(os.path.exists(marker), 'process kept running after the consumer stopped')

    def test_db_writes_are_bounded(self):
        rec = Recorder()
        commands.run([PY, '-c', 'for i in range(10000): print(i)'], recorder=rec, capture=False)
        self.assertLessEqual(rec.updates, int(rec.result.duration / 5) + 2)
        self.assertEqual(rec.result.return_code, 0)
        self.assertIn('9999', rec.result.output_tail)

    def test_tail_is_bounded(self):
        result = commands.run([PY, '-c', "[print('y' * 1000) for _ in range(500)]"], capture=False)
        self.assertLessEqual(len(result.output_tail), commands.TAIL_BYTES + 1001)

    def test_output_file_written(self):
        path = tempfile.mktemp()
        commands.run(['printf', 'a\\nb\\n'], output_path=path)
        with open(path) as f:
            self.assertEqual(f.read(), 'a\nb\n')

    def test_redaction(self):
        secret = 'S3cr3tTok3n'
        rec = Recorder()
        result = commands.run(['echo', f'Authorization: {secret}'], secrets=[secret], recorder=rec)
        self.assertNotIn(secret, result.output)
        self.assertNotIn(secret, rec.result.output_tail)
        self.assertNotIn(secret, commands.display(['curl', '-H', f'X: {secret}'], [secret]))
```

`web/tests/core/test_fsutil.py`:
```python
import os
import tempfile

from django.test import SimpleTestCase

from limes.fsutil import clear_dir, safe_rmtree


class FsutilTest(SimpleTestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.inside = os.path.join(self.root, 'scan_1')
        os.makedirs(os.path.join(self.inside, 'sub'))

    def test_removes_dir_inside_root(self):
        safe_rmtree(self.inside, roots=[self.root])
        self.assertFalse(os.path.exists(self.inside))

    def test_refuses_root_itself(self):
        with self.assertRaises(ValueError):
            safe_rmtree(self.root, roots=[self.root])

    def test_refuses_traversal_and_outside(self):
        with self.assertRaises(ValueError):
            safe_rmtree(os.path.join(self.root, '..'), roots=[self.root])
        with self.assertRaises(ValueError):
            safe_rmtree('/etc', roots=[self.root])

    def test_refuses_symlink_escape(self):
        outside = tempfile.mkdtemp()
        link = os.path.join(self.root, 'link')
        os.symlink(outside, link)
        with self.assertRaises(ValueError):
            safe_rmtree(link, roots=[self.root])
        self.assertTrue(os.path.exists(outside))

    def test_clear_dir_keeps_root(self):
        clear_dir(self.root, roots=[self.root])
        self.assertTrue(os.path.isdir(self.root))
        self.assertEqual(os.listdir(self.root), [])
```

- [ ] **Step 2: Run to see them fail**

Run: `make test` → ImportErrors for `limes.commands` and `limes.fsutil`.

- [ ] **Step 3: Implement the runner**

`web/limes/commands.py`:
```python
"""Run external tools without a shell: timeouts, process-group kill, bounded DB writes, redaction."""
import collections
import os
import shlex
import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Optional

TAIL_BYTES = 64 * 1024
FLUSH_INTERVAL = 5.0
REDACTED = '***'


class ShellCommandError(TypeError):
    pass


@dataclass
class CommandResult:
    return_code: Optional[int]
    timed_out: bool
    output_tail: str
    output: str
    duration: float


def redact(text, secrets):
    for secret in secrets:
        if secret:
            text = text.replace(secret, REDACTED)
    return text


def display(argv, secrets=()):
    return redact(shlex.join(argv), secrets)


class _Tail:
    def __init__(self, limit=TAIL_BYTES):
        self.lines = collections.deque()
        self.size = 0
        self.limit = limit

    def add(self, line):
        self.lines.append(line)
        self.size += len(line) + 1
        while self.size > self.limit and len(self.lines) > 1:
            self.size -= len(self.lines.popleft()) + 1

    def text(self):
        return '\n'.join(self.lines)


class _NullRecorder:
    def update(self, output_tail):
        pass

    def finish(self, result):
        pass


def _kill_group(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def _check_argv(argv):
    if isinstance(argv, (str, bytes)) or not argv or not all(isinstance(a, str) for a in argv):
        raise ShellCommandError('argv must be a non-empty list of strings')


def stream(argv, *, timeout=None, cwd=None, output_path=None, secrets=(), recorder=None,
           flush_interval=FLUSH_INTERVAL, clock=time.monotonic, _capture=None):
    _check_argv(argv)
    recorder = recorder or _NullRecorder()
    tail = _Tail()
    start = last_flush = clock()
    timed_out = threading.Event()
    proc = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, errors='replace', start_new_session=True)
    timer = None
    if timeout:
        def expire():
            timed_out.set()
            _kill_group(proc)
        timer = threading.Timer(timeout, expire)
        timer.daemon = True
        timer.start()
    out = open(output_path, 'a') if output_path else None
    try:
        for raw in proc.stdout:
            line = redact(raw.rstrip('\n'), secrets)
            tail.add(line)
            if out:
                out.write(line + '\n')
            if _capture is not None:
                _capture.append(line)
            yield line
            now = clock()
            if now - last_flush >= flush_interval:
                recorder.update(tail.text())
                last_flush = now
        proc.wait()
    finally:
        if timer:
            timer.cancel()
        _kill_group(proc)
        proc.wait()
        proc.stdout.close()
        if out:
            out.close()
        recorder.finish(CommandResult(
            return_code=None if timed_out.is_set() else proc.returncode,
            timed_out=timed_out.is_set(),
            output_tail=tail.text(),
            output='\n'.join(_capture) if _capture is not None else '',
            duration=clock() - start,
        ))


class _Holder:
    def __init__(self, inner):
        self.inner = inner or _NullRecorder()
        self.result = None

    def update(self, output_tail):
        self.inner.update(output_tail)

    def finish(self, result):
        self.result = result
        self.inner.finish(result)


def run(argv, *, capture=True, recorder=None, **kwargs):
    holder = _Holder(recorder)
    captured = [] if capture else None
    for _ in stream(argv, recorder=holder, _capture=captured, **kwargs):
        pass
    return holder.result
```

`web/limes/command_log.py`:
```python
from startScan.models import Command


class DbCommandRecorder:
    """Persist a command's output tail; at most one UPDATE per flush interval."""

    def __init__(self, command_obj):
        self.pk = command_obj.pk

    def update(self, output_tail):
        Command.objects.filter(pk=self.pk).update(output=output_tail)

    def finish(self, result):
        Command.objects.filter(pk=self.pk).update(output=result.output_tail, return_code=result.return_code)
```

`web/limes/fsutil.py`:
```python
import os
import shutil

from django.conf import settings

DEFAULT_ROOTS = ('/usr/src/scan_results',)


def _roots(roots):
    roots = roots or (*DEFAULT_ROOTS, settings.LIMES_RESULTS)
    return [os.path.realpath(r) for r in roots]


def safe_rmtree(path, roots=None):
    real = os.path.realpath(path)
    for root in _roots(roots):
        if real != root and real.startswith(root + os.sep):
            if os.path.islink(path):
                raise ValueError(f'refusing to delete symlink {path}')
            shutil.rmtree(real, ignore_errors=True)
            return
    raise ValueError(f'refusing to delete {path}: not inside an allowed root')


def clear_dir(root, roots=None):
    for entry in os.listdir(root):
        target = os.path.join(root, entry)
        if os.path.isdir(target) and not os.path.islink(target):
            safe_rmtree(target, roots=roots or [root])
        else:
            os.remove(target)
```
Note the symlink case: `realpath` of a link to `/tmp/x` is outside the root, so the loop raises; the `islink` guard covers a link pointing inside the root.

- [ ] **Step 4: Run tests** — `make test`, runner and fsutil tests PASS.

- [ ] **Step 5: Rewire `run_command` and `stream_command` in `web/limes/tasks.py`** (TABS)

Add near the other imports:
```python
import shlex
from limes import commands
from limes.command_log import DbCommandRecorder
```
Add above `run_command`:
```python
ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')


def legacy_argv(cmd, shell):
	# NOTE: shell=True call sites remain until plan 0B rewrites the tool stages; they run through an explicit sh -c.
	return ['/bin/sh', '-c', cmd] if shell else shlex.split(cmd)


def _append_history(history_file, cmd, return_code, output):
	if history_file:
		with open(history_file, 'a') as f:
			f.write(f'\n{cmd}\n{return_code}\n{output}\n------------------\n')
```
Replace the body of `run_command` (keep the decorator and docstring; add `timeout=None` as the last parameter):
```python
	argv = legacy_argv(cmd, shell)
	shown = commands.display(argv)
	logger.info(shown)
	command_obj = Command.objects.create(
		command=shown,
		time=timezone.now(),
		scan_history_id=scan_id,
		activity_id=activity_id)
	result = commands.run(argv, cwd=cwd, timeout=timeout, recorder=DbCommandRecorder(command_obj))
	output = result.output
	_append_history(history_file, shown, result.return_code, output)
	if remove_ansi_sequence:
		output = remove_ansi_escape_sequences(output)
	return result.return_code, output
```
Replace the body of `stream_command` (add `timeout=None` as the last parameter):
```python
	argv = legacy_argv(cmd, shell)
	shown = commands.display(argv)
	logger.info(shown)
	command_obj = Command.objects.create(
		command=shown,
		time=timezone.now(),
		scan_history_id=scan_id,
		activity_id=activity_id)
	recorder = DbCommandRecorder(command_obj)
	for line in commands.stream(argv, cwd=cwd, timeout=timeout, recorder=recorder):
		line = ANSI_ESCAPE.sub('', line).replace('\\x0d\\x0a', '\n')
		if trunc_char and line.endswith(trunc_char):
			line = line[:-1]
		try:
			yield json.loads(line)
		except json.JSONDecodeError:
			yield line
	_append_history(history_file, shown, None, '')
```
Delete any remaining code from the old bodies (the per-line `command_obj.save()` loop and the trailing return-code save).

- [ ] **Step 6: Replace shell deletions and duplicated installs**

`web/startScan/views.py`: add `from limes.fsutil import clear_dir, safe_rmtree`; replace line 483 and 966 `run_command('rm -rf ' + delete_dir)` with `safe_rmtree(delete_dir)`; replace line 765 `run_command('rm -rf /usr/src/scan_results/*')` with `clear_dir('/usr/src/scan_results')`.

`web/scanEngine/views.py:583-584` and `web/api/views.py:1321-1322`: each pair currently runs the command synchronously AND queues it again. Replace each pair with a single line:
```python
run_command.delay(install_command)      # scanEngine/views.py
run_command.delay(uninstall_command)    # api/views.py
```
(These are admin-defined tool install commands; they run as an argument list via `shlex.split`, never through a shell.)

- [ ] **Step 7: Run the suite and a lint import check**

Run: `make test`
Expected: all PASS, including `ImportTest.test_tasks_module_imports`.

- [ ] **Step 8: Commit**

```bash
git add web/limes/commands.py web/limes/command_log.py web/limes/fsutil.py web/limes/tasks.py web/startScan/views.py web/scanEngine/views.py web/api/views.py web/tests/core/test_commands.py web/tests/core/test_fsutil.py
git commit -m "fix: run tools with timeouts, group kill and bounded command logging

Per-line saves of the growing command output made DB load quadratic and
hung tools held worker slots forever."
```

---

### Task 6: Atomic scan bookkeeping and quiet notifications

**Files:**
- Create: `web/limes/db_ops.py`, `web/tests/core/test_db_ops.py`, `web/tests/core/test_notify.py`
- Modify: `web/limes/celery_custom_task.py:180-234`, `web/limes/tasks.py` (`report`, ≈ line 378-381)

**Interfaces:**
- Produces: `append_celery_id(model, pk: int, celery_id: str) -> None`; `notifications_enabled() -> bool` (in `db_ops`).

- [ ] **Step 1: Write failing tests**

`web/tests/core/test_db_ops.py`:
```python
import threading

from django.db import connection
from django.test import TransactionTestCase
from django.utils import timezone

from limes.db_ops import append_celery_id
from scanEngine.models import EngineType
from startScan.models import ScanHistory
from targetApp.models import Domain


class AppendCeleryIdTest(TransactionTestCase):
    def test_concurrent_appends_all_land(self):
        domain = Domain.objects.create(name='a.test', insert_date=timezone.now())
        engine = EngineType.objects.create(engine_name='t', yaml_configuration='{}')
        scan = ScanHistory.objects.create(domain=domain, scan_type=engine, start_scan_date=timezone.now())

        def worker(i):
            append_celery_id(ScanHistory, scan.pk, f'id-{i}')
            connection.close()

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        scan.refresh_from_db()
        self.assertEqual(sorted(scan.celery_ids), sorted(f'id-{i}' for i in range(20)))
```

`web/tests/core/test_notify.py`:
```python
from unittest import mock

from django.test import TestCase

from limes.db_ops import notifications_enabled
from scanEngine.models import Notification


class NotifyGateTest(TestCase):
    def test_disabled_without_settings(self):
        self.assertFalse(notifications_enabled())

    def test_enabled_when_status_notifs_on(self):
        Notification.objects.create(send_scan_status_notif=True)
        self.assertTrue(notifications_enabled())

    def test_task_notify_does_not_enqueue_when_disabled(self):
        from limes.tasks import port_scan
        with mock.patch('limes.tasks.send_task_notif.delay') as delay:
            port_scan.task_name = 'port_scan'
            port_scan.status = 1
            port_scan.result = port_scan.traceback = port_scan.output_path = None
            port_scan.scan_id = port_scan.engine_id = port_scan.subscan_id = None
            port_scan.notify(fields={'x': 'y'})
        delay.assert_not_called()
```

- [ ] **Step 2: Run to see them fail** — `make test` → ImportError for `limes.db_ops`.

- [ ] **Step 3: Implement `db_ops.py`**

```python
from django.contrib.postgres.fields import ArrayField
from django.db import models
from django.db.models import F, Func, Value
from django.db.models.functions import Cast

from scanEngine.models import Notification


def append_celery_id(model, pk, celery_id):
    model.objects.filter(pk=pk).update(celery_ids=Func(
        F('celery_ids'),
        Cast(Value(celery_id), models.CharField(max_length=100)),
        function='array_append',
        output_field=ArrayField(models.CharField(max_length=100)),
    ))


def notifications_enabled():
    return Notification.objects.filter(send_scan_status_notif=True).exists()
```

- [ ] **Step 4: Use them in `celery_custom_task.py`** (TABS)

Add `from limes.db_ops import append_celery_id, notifications_enabled`.
Replace `create_scan_activity` with:
```python
	def create_scan_activity(self):
		if not self.track:
			return
		celery_id = self.request.id
		self.activity = ScanActivity.objects.create(
			name=self.task_name,
			title=self.description,
			time=timezone.now(),
			status=RUNNING_TASK,
			celery_id=celery_id,
			scan_of=self.scan)
		self.activity_id = self.activity.id
		if self.scan:
			append_celery_id(ScanHistory, self.scan.pk, celery_id)
		if self.subscan:
			append_celery_id(SubScan, self.subscan.pk, celery_id)
```
Replace the persistence part of `update_scan_activity` (keep the trimming of `error_message`):
```python
		ScanActivity.objects.filter(pk=self.activity.pk).update(
			status=self.status,
			error_message=error_message,
			traceback=self.traceback,
			time=timezone.now())
		self.notify()
```
At the start of `notify`, add:
```python
		if not notifications_enabled():
			return None
```

- [ ] **Step 5: Stop `report` from overwriting concurrent fields** (`tasks.py`, inside `report`)

Replace:
```python
	else:
		scan.scan_status = status
	scan.stop_scan_date = timezone.now()
	scan.save()
```
with:
```python
	else:
		scan.scan_status = status
	scan.stop_scan_date = timezone.now()
	scan.save(update_fields=['scan_status', 'stop_scan_date'])
```

- [ ] **Step 6: Run tests** — `make test`, all PASS.

- [ ] **Step 7: Commit**

```bash
git add web/limes/db_ops.py web/limes/celery_custom_task.py web/limes/tasks.py web/tests/core/test_db_ops.py web/tests/core/test_notify.py
git commit -m "fix: update scan bookkeeping atomically and skip disabled notifications

Concurrent tasks rewrote the whole scan row and lost each other's
celery ids; every task also queued notifications nobody had enabled."
```

---

### Task 7: Remove in-task joins

**Files:**
- Create: `web/limes/urlfiles.py`, `web/tests/core/test_no_joins.py`, `web/tests/core/test_urlfiles.py`
- Modify: `web/limes/tasks.py` (`port_scan` nmap block ≈ lines 1455-1475; `fetch_url` ≈ lines 1890-1927; import of `allow_join_result` at line 18)

**Interfaces:**
- Produces: `merge_url_files(results_dir: str, input_path: str, output_path: str, ignore_exts: Iterable[str] = ()) -> int` (number of unique URLs written).

Deviation from the spec's R1 test: a unit test that reproduces the deadlock would need the full tool stack inside a 1-slot worker. Instead, the static test below forbids the join primitive, and the `bench-scans` run in Tasks 2 and 13 (20 concurrent scans of the lab target, which today exercises both join sites) is the end-to-end proof: it must show `stuck=0`.

- [ ] **Step 1: Write failing tests**

`web/tests/core/test_no_joins.py`:
```python
import pathlib

from django.test import SimpleTestCase

WEB = pathlib.Path(__file__).resolve().parents[2]


class NoJoinInsideTasksTest(SimpleTestCase):
    def test_no_allow_join_result(self):
        offenders = [str(p) for p in list((WEB / 'limes').glob('*.py')) + list((WEB / 'api').glob('*.py'))
                     if 'allow_join_result' in p.read_text()]
        self.assertEqual(offenders, [])
```

`web/tests/core/test_urlfiles.py`:
```python
import os
import tempfile

from django.test import SimpleTestCase

from limes.urlfiles import merge_url_files


class MergeUrlFilesTest(SimpleTestCase):
    def test_merge_dedupe_sort_filter(self):
        d = tempfile.mkdtemp()
        with open(os.path.join(d, 'urls_katana.txt'), 'w') as f:
            f.write('https://a.test/b\nhttps://a.test/x.png?v=1\n\n')
        with open(os.path.join(d, 'urls_gau.txt'), 'w') as f:
            f.write('https://a.test/a\nhttps://a.test/b\n')
        inp = os.path.join(d, 'input.txt')
        with open(inp, 'w') as f:
            f.write('https://a.test/\n')
        out = os.path.join(d, 'out.txt')
        n = merge_url_files(d, inp, out, ignore_exts=['png'])
        with open(out) as f:
            self.assertEqual(f.read().splitlines(), ['https://a.test/', 'https://a.test/a', 'https://a.test/b'])
        self.assertEqual(n, 3)

    def test_missing_input_is_ignored(self):
        d = tempfile.mkdtemp()
        out = os.path.join(d, 'out.txt')
        self.assertEqual(merge_url_files(d, os.path.join(d, 'nope.txt'), out), 0)
```

- [ ] **Step 2: Run to see them fail** — `make test`: `test_no_allow_join_result` lists `limes/tasks.py`; `urlfiles` ImportError.

- [ ] **Step 3: Implement `urlfiles.py`**

```python
import glob
import os
import re


def merge_url_files(results_dir, input_path, output_path, ignore_exts=()):
    pattern = re.compile(r'\.(' + '|'.join(map(re.escape, ignore_exts)) + r').*', re.I) if ignore_exts else None
    paths = sorted(glob.glob(os.path.join(results_dir, 'urls_*')))
    if os.path.exists(input_path):
        paths.append(input_path)
    urls = set()
    for path in paths:
        with open(path, errors='replace') as f:
            for line in f:
                url = line.strip()
                if url and not (pattern and pattern.search(url)):
                    urls.add(url)
    with open(output_path, 'w') as f:
        f.writelines(u + '\n' for u in sorted(urls))
    return len(urls)
```

- [ ] **Step 4: Rewrite the `port_scan` nmap block** (TABS) — replace from `# Process nmap results: 1 process per host` through `results = task.get()` with:
```python
	# NOTE: nmap runs in-process, one host after another; plan 0B batches hosts into one invocation.
	if nmap_enabled:
		logger.warning('Starting nmap scans ...')
		for host, port_list in ports_data.items():
			ctx_nmap = ctx.copy()
			ctx_nmap['description'] = get_task_title(f'nmap_{host}', self.scan_id, self.subscan_id)
			ctx_nmap['track'] = False
			nmap(
				cmd=nmap_cmd,
				ports=port_list,
				host=host,
				script=nmap_script,
				script_args=nmap_script_args,
				max_rate=rate_limit,
				ctx=ctx_nmap)
```

- [ ] **Step 5: Rewrite the `fetch_url` run + cleanup** — replace from `tasks = group(` through the `with allow_join_result(): task.get()` block (including the `sort_output`/`grep_ext_filtered_output`/`cleanup` construction) with:
```python
	# NOTE: crawlers run one after another inside this task; plan 0B keeps only katana + gau.
	for tool, cmd in cmd_map.items():
		if tool in tools:
			run_command(
				cmd,
				shell=True,
				scan_id=self.scan_id,
				activity_id=self.activity_id)
	merge_url_files(
		results_dir=self.results_dir,
		input_path=input_path,
		output_path=self.output_path,
		ignore_exts=ignore_file_extension or [])
```
Add `from limes.urlfiles import merge_url_files` to the imports and delete `from celery.result import allow_join_result`. If `chord` / `group` imports become unused, leave them (other tasks may use them; only remove an import your change orphaned — check with `grep -n "chord(\|group(" web/limes/tasks.py`).

- [ ] **Step 6: Run tests** — `make test`, all PASS.

- [ ] **Step 7: Commit**

```bash
git add web/limes/urlfiles.py web/limes/tasks.py web/tests/core/test_no_joins.py web/tests/core/test_urlfiles.py
git commit -m "fix: stop tasks from blocking on child tasks

port_scan and fetch_url waited on subtasks inside a worker slot; with all
slots waiting, the subtasks never ran and scans hung forever."
```

---

### Task 8: Celery routing, time limits and recovery settings

**Files:**
- Create: `web/limes/celery_routing.py`, `web/tests/core/test_celery_config.py`
- Modify: `web/limes/settings.py:199-208`, `web/limes/celery.py`, `web/limes/tasks.py` (all `@app.task(...)` decorators), `web/api/shared_api_tasks.py:9,131`, `web/requirements.txt`, `web/limes/celery_custom_task.py` (`write_results`)

**Interfaces:**
- Produces: `SCAN`, `IO`, `ORCHESTRATE` queue names; `TASK_PLAN: dict[str, tuple[str, int]]` (task name → (queue, hard limit seconds)); `task_routes() -> dict`; `task_annotations() -> dict`; `MAX_TIME_LIMIT: int`. Task 9 adds `'reap_stuck_scans'` to `TASK_PLAN`.

- [ ] **Step 1: Write failing tests**

`web/tests/core/test_celery_config.py`:
```python
import os
import tempfile

from django.conf import settings
from django.test import SimpleTestCase

from limes import celery_routing
from limes.celery import app


def registered_tasks():
    import api.shared_api_tasks  # noqa: F401
    import limes.tasks  # noqa: F401
    return {name for name in app.tasks if not name.startswith('celery.')}


class CeleryConfigTest(SimpleTestCase):
    def test_every_task_is_planned(self):
        self.assertEqual(registered_tasks() - set(celery_routing.TASK_PLAN), set())

    def test_no_task_pins_its_own_queue(self):
        pinned = [n for n in registered_tasks() if getattr(app.tasks[n], 'queue', None)]
        self.assertEqual(pinned, [])

    def test_only_three_queues(self):
        queues = {q for q, _ in celery_routing.TASK_PLAN.values()}
        self.assertEqual(queues, {'scan', 'io', 'orchestrate'})

    def test_limits(self):
        for name, ann in celery_routing.task_annotations().items():
            self.assertLess(ann['soft_time_limit'], ann['time_limit'], name)
        self.assertGreater(settings.CELERY_BROKER_TRANSPORT_OPTIONS['visibility_timeout'],
                           celery_routing.MAX_TIME_LIMIT)

    def test_recovery_flags(self):
        self.assertTrue(app.conf.task_acks_late)
        self.assertTrue(app.conf.task_reject_on_worker_lost)
        self.assertEqual(app.conf.worker_prefetch_multiplier, 1)


class RedeliveryTest(SimpleTestCase):
    def test_write_results_tolerates_existing_file(self):
        from limes.celery_custom_task import LimesTask
        task = LimesTask()
        path = tempfile.mktemp()
        with open(path, 'w') as f:
            f.write('old')
        task.result, task.output_path, task.task_name = ['new'], path, 't'
        task.write_results()
        with open(path) as f:
            self.assertIn('new', f.read())
```

- [ ] **Step 2: Run to see them fail** — `make test` → ImportError for `celery_routing`.

- [ ] **Step 3: Implement `celery_routing.py`**

```python
"""Single source of truth for task queues and time limits."""
SCAN, IO, ORCHESTRATE = 'scan', 'io', 'orchestrate'
MIN, HOUR = 60, 3600
SOFT_MARGIN = 120

TASK_PLAN = {
    # discovery 2 h
    'subdomain_discovery': (SCAN, 2 * HOUR), 'osint': (SCAN, 2 * HOUR), 'osint_discovery': (SCAN, 2 * HOUR),
    'dorking': (SCAN, 2 * HOUR), 'theHarvester': (SCAN, 2 * HOUR), 'h8mail': (SCAN, 2 * HOUR),
    # port scan 2 h
    'port_scan': (SCAN, 2 * HOUR), 'nmap': (SCAN, 2 * HOUR),
    # crawl / probe 2 h
    'fetch_url': (SCAN, 2 * HOUR), 'http_crawl': (SCAN, 2 * HOUR), 'screenshot': (SCAN, 2 * HOUR),
    'waf_detection': (SCAN, 2 * HOUR), 'dir_file_fuzz': (SCAN, 2 * HOUR), 'run_command': (SCAN, 2 * HOUR),
    # DAST 6 h
    'vulnerability_scan': (SCAN, 6 * HOUR), 'nuclei_individual_severity_module': (SCAN, 6 * HOUR),
    'nuclei_scan': (SCAN, 6 * HOUR), 'dalfox_xss_scan': (SCAN, 6 * HOUR), 'crlfuzz_scan': (SCAN, 6 * HOUR),
    's3scanner': (SCAN, 6 * HOUR),
    # parsing, enrichment, notifications 15 min
    'send_notif': (IO, 15 * MIN), 'send_scan_notif': (IO, 15 * MIN), 'send_task_notif': (IO, 15 * MIN),
    'send_file_to_discord': (IO, 15 * MIN), 'send_hackerone_report': (IO, 15 * MIN),
    'parse_nmap_results': (IO, 15 * MIN), 'geo_localize': (IO, 15 * MIN), 'query_whois': (IO, 15 * MIN),
    'remove_duplicate_endpoints': (IO, 15 * MIN), 'query_reverse_whois': (IO, 15 * MIN),
    'query_ip_history': (IO, 15 * MIN), 'llm_vulnerability_description': (IO, 15 * MIN),
    'import_hackerone_programs_task': (IO, 15 * MIN), 'sync_bookmarked_programs_task': (IO, 15 * MIN),
    # orchestration 15 min
    'initiate_scan': (ORCHESTRATE, 15 * MIN), 'initiate_subscan': (ORCHESTRATE, 15 * MIN),
    'report': (ORCHESTRATE, 15 * MIN),
}

MAX_TIME_LIMIT = max(limit for _, limit in TASK_PLAN.values())


def task_routes():
    return {name: {'queue': queue} for name, (queue, _) in TASK_PLAN.items()}


def task_annotations():
    return {name: {'time_limit': limit, 'soft_time_limit': limit - SOFT_MARGIN}
            for name, (_, limit) in TASK_PLAN.items()}
```

- [ ] **Step 4: Replace the Celery block in `settings.py`** (lines 199-208, the block starting `CELERY_BROKER_URL`):

```python
from limes import celery_routing

CELERY_BROKER_URL = env("CELERY_BROKER", default="redis://redis:6379/0")
CELERY_RESULT_BACKEND = env("CELERY_BROKER", default="redis://redis:6379/0")
CELERY_ENABLE_UTC = False
CELERY_TIMEZONE = 'UTC'
CELERY_IGNORE_RESULTS = False
CELERY_EAGER_PROPAGATES_EXCEPTIONS = True
CELERY_TRACK_STARTED = True
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True
CELERY_IMPORTS = ('limes.tasks', 'api.shared_api_tasks')
CELERY_TASK_ROUTES = celery_routing.task_routes()
CELERY_TASK_ANNOTATIONS = celery_routing.task_annotations()
CELERY_TASK_DEFAULT_QUEUE = celery_routing.IO
CELERY_TASK_ACKS_LATE = True
CELERY_TASK_REJECT_ON_WORKER_LOST = True
CELERY_WORKER_PREFETCH_MULTIPLIER = 1
CELERY_WORKER_AUTOSCALER = 'limes.autoscale:MemoryAwareAutoscaler'
CELERY_BROKER_TRANSPORT_OPTIONS = {'visibility_timeout': celery_routing.MAX_TIME_LIMIT + celery_routing.HOUR}
CELERY_RESULT_BACKEND_TRANSPORT_OPTIONS = CELERY_BROKER_TRANSPORT_OPTIONS
CELERY_RESULT_EXPIRES = 24 * celery_routing.HOUR
```

- [ ] **Step 5: Remove per-task queue pins**

Run:
```bash
sed -i -E "s/, *queue='[A-Za-z_]+'//; s/queue='[A-Za-z_]+', *//" web/limes/tasks.py web/api/shared_api_tasks.py
grep -nE "queue=" web/limes/tasks.py web/api/shared_api_tasks.py web/limes/common_func.py web/startScan/views.py web/api/views.py
```
Expected: the grep prints nothing. If it prints `apply_async(..., queue=...)` or `.set(queue=...)` calls, delete the `queue=` argument from each.

- [ ] **Step 6: Patch psycopg2 for gevent workers**

`web/requirements.txt`: add `psycogreen==1.0.2` and `django-redis==5.4.0`.
`web/limes/celery.py`, after `import os`:
```python
if os.environ.get('CELERY_POOL') == 'gevent':
    from psycogreen.gevent import patch_psycopg
    patch_psycopg()
```

- [ ] **Step 7: Make `write_results` safe on redelivery** (`celery_custom_task.py`, TABS)

Replace the `if not os.path.exists(self.output_path):` guard so the file is always (re)written:
```python
		with open(self.output_path, 'w') as f:
			if is_json_results:
				json.dump(self.result, f, indent=4)
			else:
				f.write(self.result)
		logger.warning(f'Wrote {self.task_name} results to {self.output_path}')
```

- [ ] **Step 8: Rebuild and run tests**

Run: `docker compose -p limes-test -f docker-compose.test.yml build test && make test`
Expected: all PASS.

- [ ] **Step 9: Commit**

```bash
git add web/limes/celery_routing.py web/limes/settings.py web/limes/celery.py web/limes/tasks.py web/api/shared_api_tasks.py web/requirements.txt web/limes/celery_custom_task.py web/tests/core/test_celery_config.py
git commit -m "fix: route tasks to three queues with time limits and late acks

Tasks had no limits and were acked on receipt, so a hung tool or a dead
worker left scans running forever."
```

---

### Task 9: Stuck-scan reaper

**Files:**
- Create: `web/limes/reaper.py`, `web/tests/core/test_reaper.py`
- Modify: `web/limes/celery_routing.py`, `web/limes/settings.py`

**Interfaces:**
- Consumes: `celery_routing.MAX_TIME_LIMIT`, `tasks.report`.
- Produces: `STUCK_AFTER: timedelta`; `find_stuck_scans(now) -> QuerySet[ScanHistory]`; task `reap_stuck_scans() -> list[int]` (reaped scan ids).

- [ ] **Step 1: Write failing tests**

`web/tests/core/test_reaper.py`:
```python
from datetime import timedelta
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from limes.definitions import FAILED_TASK, INITIATED_TASK, RUNNING_TASK
from limes.reaper import STUCK_AFTER, reap_stuck_scans
from scanEngine.models import EngineType
from startScan.models import ScanActivity, ScanHistory
from targetApp.models import Domain


class ReaperTest(TestCase):
    def setUp(self):
        self.domain = Domain.objects.create(name='r.test', insert_date=timezone.now())
        self.engine = EngineType.objects.create(engine_name='t', yaml_configuration='{}')

    def scan(self, status, started_ago, activity_ago=None):
        now = timezone.now()
        scan = ScanHistory.objects.create(domain=self.domain, scan_type=self.engine,
                                          start_scan_date=now - started_ago, scan_status=status)
        if activity_ago is not None:
            ScanActivity.objects.create(scan_of=scan, title='t', name='t', status=RUNNING_TASK,
                                        time=now - activity_ago)
        return scan

    @mock.patch('limes.reaper.report.delay')
    def test_reaps_silent_running_scan(self, delay):
        old = STUCK_AFTER + timedelta(minutes=5)
        stuck = self.scan(RUNNING_TASK, old, activity_ago=old)
        self.assertEqual(reap_stuck_scans(), [stuck.pk])
        self.assertEqual(ScanActivity.objects.get(scan_of=stuck).status, FAILED_TASK)
        delay.assert_called_once()
        self.assertEqual(delay.call_args.kwargs['ctx']['scan_history_id'], stuck.pk)

    @mock.patch('limes.reaper.report.delay')
    def test_keeps_scan_with_recent_activity(self, delay):
        self.scan(RUNNING_TASK, STUCK_AFTER * 3, activity_ago=timedelta(minutes=1))
        self.assertEqual(reap_stuck_scans(), [])
        delay.assert_not_called()

    @mock.patch('limes.reaper.report.delay')
    def test_reaps_scan_stuck_in_initiated(self, delay):
        stuck = self.scan(INITIATED_TASK, STUCK_AFTER + timedelta(minutes=5))
        self.assertEqual(reap_stuck_scans(), [stuck.pk])

    @mock.patch('limes.reaper.report.delay')
    def test_ignores_finished_scans(self, delay):
        self.scan(2, STUCK_AFTER * 2, activity_ago=STUCK_AFTER * 2)
        self.assertEqual(reap_stuck_scans(), [])
```

- [ ] **Step 2: Run to see it fail** — ImportError for `limes.reaper`.

- [ ] **Step 3: Implement `reaper.py`**

```python
from datetime import timedelta

from django.db.models import F, Max
from django.db.models.functions import Coalesce
from django.utils import timezone

from limes.celery import app
from limes.celery_routing import MAX_TIME_LIMIT
from limes.definitions import FAILED_TASK, INITIATED_TASK, RUNNING_TASK
from limes.tasks import report
from startScan.models import ScanActivity, ScanHistory

STUCK_AFTER = timedelta(seconds=MAX_TIME_LIMIT) + timedelta(minutes=30)
REAPED_MSG = 'Marked failed: no task progress within the time budget'


def find_stuck_scans(now):
    return (ScanHistory.objects
            .filter(scan_status__in=[RUNNING_TASK, INITIATED_TASK])
            .annotate(last_seen=Coalesce(Max('scanactivity__time'), F('start_scan_date')))
            .filter(last_seen__lt=now - STUCK_AFTER))


@app.task(name='reap_stuck_scans', bind=False)
def reap_stuck_scans():
    now = timezone.now()
    reaped = []
    for scan in find_stuck_scans(now):
        ScanActivity.objects.filter(scan_of=scan, status=RUNNING_TASK).update(
            status=FAILED_TASK, error_message=REAPED_MSG, time=now)
        ScanHistory.objects.filter(pk=scan.pk).update(error_message=REAPED_MSG)
        report.delay(ctx={'scan_history_id': scan.pk, 'engine_id': scan.scan_type_id})
        reaped.append(scan.pk)
    return reaped
```

- [ ] **Step 4: Register and schedule**

`celery_routing.py`: add `'reap_stuck_scans': (ORCHESTRATE, 15 * MIN),` to the orchestration block of `TASK_PLAN`.
`settings.py`: change `CELERY_IMPORTS` to `('limes.tasks', 'limes.reaper', 'api.shared_api_tasks')` and add:
```python
CELERY_BEAT_SCHEDULE = {
    'reap-stuck-scans': {'task': 'reap_stuck_scans', 'schedule': 300.0},
}
```
(`django_celery_beat`'s DatabaseScheduler installs `beat_schedule` entries into its tables at startup.)

`test_celery_config.registered_tasks()` must also `import limes.reaper  # noqa: F401`.

- [ ] **Step 5: Run tests** — `make test`, all PASS.

- [ ] **Step 6: Commit**

```bash
git add web/limes/reaper.py web/limes/celery_routing.py web/limes/settings.py web/tests/core/test_reaper.py web/tests/core/test_celery_config.py
git commit -m "feat: fail scans that stop making progress

A worker killed mid-task never reported back, so its scan stayed
running in the UI indefinitely."
```

---

### Task 10: Fast dashboard (aggregates, Redis cache, indexes)

**Files:**
- Create: `web/dashboard/stats.py`, `web/startScan/migrations/0003_phase0_indexes.py`, `web/tests/core/test_dashboard_stats.py`
- Modify: `web/dashboard/views.py:32-174` (`index`), `web/limes/settings.py` (`CACHES`, `DATABASES`), `web/startScan/models.py` (Meta indexes), `web/limes/tasks.py` (`report`)

**Interfaces:**
- Produces: `project_stats(project) -> dict` (every context key the old `index` view computed except `project` and `dashboard_data_active`); `invalidate(project_id: int) -> None`; `STATS_TTL = 60`.

- [ ] **Step 1: Write failing tests**

`web/tests/core/test_dashboard_stats.py`:
```python
from django.core.cache import cache
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from dashboard.models import Project
from dashboard.stats import invalidate, project_stats
from scanEngine.models import EngineType
from startScan.models import EndPoint, IpAddress, ScanHistory, Subdomain, Vulnerability
from targetApp.models import Domain


class StatsTest(TestCase):
    def setUp(self):
        cache.clear()
        now = timezone.now()
        self.project = Project.objects.create(name='p', slug='p', insert_date=now)
        domain = Domain.objects.create(name='d.test', project=self.project, insert_date=now)
        engine = EngineType.objects.create(engine_name='t', yaml_configuration='{}')
        scan = ScanHistory.objects.create(domain=domain, scan_type=engine, start_scan_date=now, scan_status=2)
        s1 = Subdomain.objects.create(name='a.d.test', scan_history=scan, target_domain=domain, http_status=200, discovered_date=now)
        Subdomain.objects.create(name='b.d.test', scan_history=scan, target_domain=domain, http_status=0, discovered_date=now)
        ip1, ip2 = IpAddress.objects.create(address='192.0.2.1'), IpAddress.objects.create(address='192.0.2.2')
        s1.ip_addresses.add(ip1, ip2)
        EndPoint.objects.create(http_url='https://a.d.test/', name='a', url='https://a.d.test/', scan_history=scan,
                                target_domain=domain, subdomain=s1, http_status=200, discovered_date=now)
        for sev in (0, 3, 3, 4):
            Vulnerability.objects.create(name='v', severity=sev, scan_history=scan, target_domain=domain, discovered_date=now)

    def test_counts(self):
        s = project_stats(self.project)
        self.assertEqual((s['domain_count'], s['subdomain_count'], s['alive_count']), (1, 2, 1))
        self.assertEqual(s['subdomain_with_ip_count'], 1)  # distinct, not one row per IP
        self.assertEqual((s['high_count'], s['critical_count'], s['info_count']), (2, 1, 1))
        self.assertEqual(s['total_vul_ignore_info_count'], 3)
        self.assertEqual(s['subdomains_in_last_week'][-1], 2)
        self.assertEqual(len(s['last_7_dates']), 7)

    def test_empty_project_returns_zeros(self):
        empty = Project.objects.create(name='e', slug='e', insert_date=timezone.now())
        s = project_stats(empty)
        self.assertEqual((s['subdomain_count'], s['critical_count'], s['total_vul_count']), (0, 0, 0))
        self.assertEqual(s['vulns_in_last_week'], [0] * 7)

    def test_query_budget_and_cache_hit(self):
        with CaptureQueriesContext(connection) as cold:
            project_stats(self.project)
        self.assertLessEqual(len(cold.captured_queries), 25)
        with CaptureQueriesContext(connection) as warm:
            project_stats(self.project)
        self.assertEqual(len(warm.captured_queries), 0)

    def test_invalidate(self):
        project_stats(self.project)
        invalidate(self.project.id)
        with CaptureQueriesContext(connection) as ctx:
            project_stats(self.project)
        self.assertGreater(len(ctx.captured_queries), 0)
```
If `IpAddress` or `EndPoint` creation fails on a required field not shown above, add that field with a literal value; do not change the assertions.

- [ ] **Step 2: Run to see it fail** — ImportError for `dashboard.stats`.

- [ ] **Step 3: Switch caching to Redis and prepare for pgbouncer** (`settings.py`)

Replace the `CACHES` block with:
```python
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': env('CACHE_URL', default='redis://redis:6379/1'),
        'TIMEOUT': 60 * 30,
    }
}
```
In `DATABASES['default']` add:
```python
        'CONN_MAX_AGE': 0,
        'DISABLE_SERVER_SIDE_CURSORS': True,
```

- [ ] **Step 4: Implement `dashboard/stats.py`**

```python
from datetime import timedelta

from django.core.cache import cache
from django.db.models import Count, Q
from django.db.models.functions import TruncDay
from django.utils import timezone

from startScan.models import (CountryISO, CveId, CweId, EndPoint, IpAddress, Port, ScanActivity, ScanHistory,
                              Subdomain, Technology, Vulnerability, VulnerabilityTags)
from targetApp.models import Domain

STATS_TTL = 60
SEVERITIES = {'unknown_count': -1, 'info_count': 0, 'low_count': 1, 'medium_count': 2, 'high_count': 3, 'critical_count': 4}


def _key(project_id):
    return f'dashboard:stats:{project_id}'


def invalidate(project_id):
    cache.delete(_key(project_id))


def _last_week(qs, field, dates):
    rows = (qs.filter(**{f'{field}__gte': timezone.now() - timedelta(days=7)})
            .annotate(day=TruncDay(field)).values('day').annotate(n=Count('id')))
    by_day = {row['day'].date(): row['n'] for row in rows}
    return [by_day.get(d, 0) for d in reversed(dates)]


def _compute(project):
    domains = Domain.objects.filter(project=project)
    scans = ScanHistory.objects.filter(domain__project=project)
    subdomains = Subdomain.objects.filter(scan_history__domain__project=project)
    endpoints = EndPoint.objects.filter(scan_history__domain__project=project)
    vulns = Vulnerability.objects.filter(scan_history__domain__project=project)
    ips = IpAddress.objects.filter(ip_addresses__in=subdomains)

    sub = subdomains.aggregate(total=Count('id'), alive=Count('id', filter=~Q(http_status=0)))
    ep = endpoints.aggregate(total=Count('id'), alive=Count('id', filter=Q(http_status=200)))
    sev = vulns.aggregate(**{k: Count('id', filter=Q(severity=v)) for k, v in SEVERITIES.items()})
    dates = [(timezone.now() - timedelta(days=i)).date() for i in range(7)]

    stats = {
        'domain_count': domains.count(),
        'scan_count': scans.count(),
        'subdomain_count': sub['total'] or 0,
        'alive_count': sub['alive'] or 0,
        'subdomain_with_ip_count': subdomains.filter(ip_addresses__isnull=False).distinct().count(),
        'endpoint_count': ep['total'] or 0,
        'endpoint_alive_count': ep['alive'] or 0,
        **{k: v or 0 for k, v in sev.items()},
        'targets_in_last_week': _last_week(domains, 'insert_date', dates),
        'subdomains_in_last_week': _last_week(subdomains, 'discovered_date', dates),
        'vulns_in_last_week': _last_week(vulns, 'discovered_date', dates),
        'scans_in_last_week': _last_week(scans, 'start_scan_date', dates),
        'endpoints_in_last_week': _last_week(endpoints, 'discovered_date', dates),
        'last_7_dates': dates,
        'vulnerability_feed': list(vulns.order_by('-discovered_date')[:50]),
        'activity_feed': list(ScanActivity.objects.filter(scan_of__in=scans).order_by('-time')[:50]),
        'total_ips': ips.count(),
        'most_used_port': list(Port.objects.filter(ports__in=ips).annotate(count=Count('ports')).order_by('-count')[:7]),
        'most_used_ip': list(ips.annotate(count=Count('ip_addresses')).order_by('-count').exclude(ip_addresses__isnull=True)[:7]),
        'most_used_tech': list(Technology.objects.filter(technologies__in=subdomains).annotate(count=Count('technologies')).order_by('-count')[:7]),
        'most_common_cve': list(CveId.objects.filter(cve_ids__in=vulns).annotate(nused=Count('cve_ids')).order_by('-nused').values('name', 'nused')[:7]),
        'most_common_cwe': list(CweId.objects.filter(cwe_ids__in=vulns).annotate(nused=Count('cwe_ids')).order_by('-nused').values('name', 'nused')[:7]),
        'most_common_tags': list(VulnerabilityTags.objects.filter(vuln_tags__in=vulns).annotate(nused=Count('vuln_tags')).order_by('-nused').values('name', 'nused')[:7]),
        'asset_countries': list(CountryISO.objects.filter(ipaddress__in=ips).annotate(count=Count('ipaddress')).order_by('-count')),
    }
    stats['total_vul_count'] = sum(stats[k] for k in SEVERITIES)
    stats['total_vul_ignore_info_count'] = stats['total_vul_count'] - stats['info_count'] - stats['unknown_count']
    return stats


def project_stats(project):
    stats = cache.get(_key(project.id))
    if stats is None:
        stats = _compute(project)
        cache.set(_key(project.id), stats, STATS_TTL)
    return stats
```
Note: `total_vul_ignore_info_count` previously summed low+medium+high+critical, which equals total − info − unknown; the `last_7_dates` order matches the old view (newest first), and the `*_in_last_week` lists are oldest-first, as the old view produced after `.reverse()`. Also check `web/startScan/models.py` for the real `related_name` of `IpAddress→Subdomain` (`ip_addresses`), `Port` (`ports`), `Technology` (`technologies`), `CveId`/`CweId`/`VulnerabilityTags` (`cve_ids`, `cwe_ids`, `vuln_tags`) — these are copied from the old view and must stay identical.

- [ ] **Step 5: Use it in the view** (`dashboard/views.py`) — replace the body of `index` after the `Project` lookup with:
```python
    context = dict(project_stats(project))
    context.update({'dashboard_data_active': 'active', 'project': project})
    return render(request, 'dashboard/index.html', context)
```
Add `from dashboard.stats import project_stats`. Remove imports that only the old body used (check each with grep in the file before deleting).

- [ ] **Step 6: Invalidate when a scan finishes** — in `tasks.report`, after `scan.save(update_fields=[...])`:
```python
	from dashboard.stats import invalidate
	invalidate(scan.domain.project_id)
```

- [ ] **Step 7: Add indexes**

First check for model/migration drift:
Run: `make manage ARGS="makemigrations --check --dry-run"`
If it reports changes, generate them first: `make manage ARGS="makemigrations"`, review the generated files, and commit them as `chore: commit missing model migrations` before continuing.

In `web/startScan/models.py` add `class Meta` (TABS) with explicit names:
- `Subdomain`: `indexes = [models.Index(fields=['scan_history', 'discovered_date'], name='sub_scan_disc_idx'), models.Index(fields=['scan_history', 'http_status'], name='sub_scan_status_idx')]`
- `EndPoint`: `indexes = [models.Index(fields=['scan_history', 'discovered_date'], name='ep_scan_disc_idx'), models.Index(fields=['scan_history', 'http_status'], name='ep_scan_status_idx')]`
- `Vulnerability`: `indexes = [models.Index(fields=['scan_history', 'severity'], name='vuln_scan_sev_idx'), models.Index(fields=['scan_history', 'discovered_date'], name='vuln_scan_disc_idx')]`
- `ScanActivity`: `indexes = [models.Index(fields=['scan_of', 'time'], name='act_scan_time_idx'), models.Index(fields=['scan_of', 'status'], name='act_scan_status_idx')]`
- `ScanHistory`: `indexes = [models.Index(fields=['scan_status'], name='scan_status_idx'), models.Index(fields=['domain', 'start_scan_date'], name='scan_domain_start_idx')]`
If a model already has a `Meta`, add `indexes` to it.

`web/startScan/migrations/0003_phase0_indexes.py` (set `dependencies` to the newest startScan migration — `0002_auto_20240911_0145`, or the one generated by the drift check):
```python
from django.contrib.postgres.operations import AddIndexConcurrently
from django.db import migrations, models


class Migration(migrations.Migration):
    atomic = False
    dependencies = [('startScan', '0002_auto_20240911_0145')]

    operations = [
        AddIndexConcurrently('subdomain', models.Index(fields=['scan_history', 'discovered_date'], name='sub_scan_disc_idx')),
        AddIndexConcurrently('subdomain', models.Index(fields=['scan_history', 'http_status'], name='sub_scan_status_idx')),
        AddIndexConcurrently('endpoint', models.Index(fields=['scan_history', 'discovered_date'], name='ep_scan_disc_idx')),
        AddIndexConcurrently('endpoint', models.Index(fields=['scan_history', 'http_status'], name='ep_scan_status_idx')),
        AddIndexConcurrently('vulnerability', models.Index(fields=['scan_history', 'severity'], name='vuln_scan_sev_idx')),
        AddIndexConcurrently('vulnerability', models.Index(fields=['scan_history', 'discovered_date'], name='vuln_scan_disc_idx')),
        AddIndexConcurrently('scanactivity', models.Index(fields=['scan_of', 'time'], name='act_scan_time_idx')),
        AddIndexConcurrently('scanactivity', models.Index(fields=['scan_of', 'status'], name='act_scan_status_idx')),
        AddIndexConcurrently('scanhistory', models.Index(fields=['scan_status'], name='scan_status_idx')),
        AddIndexConcurrently('scanhistory', models.Index(fields=['domain', 'start_scan_date'], name='scan_domain_start_idx')),
    ]
```
Run: `make manage ARGS="makemigrations --check --dry-run"`
Expected: `No changes detected`.

- [ ] **Step 8: Run tests** — rebuild (`django-redis` added in Task 8) and `make test`, all PASS.

- [ ] **Step 9: Commit**

```bash
git add web/dashboard/stats.py web/dashboard/views.py web/limes/settings.py web/limes/tasks.py web/startScan/models.py web/startScan/migrations/0003_phase0_indexes.py web/tests/core/test_dashboard_stats.py
git commit -m "perf: serve dashboard from cached aggregates with supporting indexes

The dashboard ran about fifty uncached count and join queries per page
load across every subdomain and endpoint of a project."
```

---

### Task 11: Services, image and startup

**Files:**
- Create: `web/limes/health.py`, `web/migrate-entrypoint.sh`, `web/tests/core/test_health.py`
- Modify (rewrite): `docker-compose.yml`, `docker-compose.dev.yml`, `web/entrypoint.sh`, `web/celery-entrypoint.sh`, `web/beat-entrypoint.sh`
- Modify: `web/Dockerfile`, `web/limes/urls.py`, `web/limes/settings.py` (`LOGIN_REQUIRED_IGNORE_VIEW_NAMES`), `Makefile` (`SERVICES`)

**Interfaces:**
- Consumes: `sizing.py` (as a script), `CELERY_WORKER_AUTOSCALER`, `CACHE_URL`.
- Produces: `GET /healthz` → `200 {"status": "ok"}` or `503 {"status": "error", "failed": [...]}`; compose services `db, redis, pgbouncer, migrate, web, worker-scan, worker-io, worker-orch, beat, proxy, ollama`.

- [ ] **Step 1: Health endpoint test**

`web/tests/core/test_health.py`:
```python
from unittest import mock

from django.test import TestCase


class HealthTest(TestCase):
    def test_ok_without_login(self):
        resp = self.client.get('/healthz')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()['status'], 'ok')

    def test_reports_failed_cache(self):
        with mock.patch('limes.health.cache.set', side_effect=ConnectionError('down')):
            resp = self.client.get('/healthz')
        self.assertEqual(resp.status_code, 503)
        self.assertEqual(resp.json()['failed'], ['cache'])
```
Run `make test` → 404/302 failures.

- [ ] **Step 2: Implement**

`web/limes/health.py`:
```python
from django.core.cache import cache
from django.db import connection
from django.http import JsonResponse


def healthz(request):
    failed = []
    try:
        connection.ensure_connection()
    except Exception:
        failed.append('database')
    try:
        cache.set('healthz', 1, 5)
    except Exception:
        failed.append('cache')
    if failed:
        return JsonResponse({'status': 'error', 'failed': failed}, status=503)
    return JsonResponse({'status': 'ok'})
```
`web/limes/urls.py`: add `from limes.health import healthz` and `path('healthz', healthz, name='healthz'),` as the first entry of `urlpatterns`.
`settings.py`: append `'healthz'` to `LOGIN_REQUIRED_IGNORE_VIEW_NAMES`.
Run `make test` → PASS.

- [ ] **Step 3: Move every install out of the Celery entrypoint into the Dockerfile**

Append to `web/Dockerfile` before `# Copy source code`, translating `celery-entrypoint.sh` lines 45-194 into build steps (behaviour unchanged; plan 0B deletes the tools it removes):
```dockerfile
# Firefox for EyeWitness (removed in plan 0B)
RUN printf 'Package: *\nPin: release o=LP-PPA-mozillateam\nPin-Priority: 1001\n\nPackage: firefox\nPin: version 1:1snap1-0ubuntu2\nPin-Priority: -1\n' > /etc/apt/preferences.d/mozilla-firefox \
    && apt update && apt install -y firefox && rm -rf /var/lib/apt/lists/*

RUN sed -i 's/purge()/truncate()/g' /usr/local/lib/python3.10/dist-packages/whatportis/cli.py \
    && (yes | whatportis --update)

RUN mkdir -p /usr/src/wordlist /usr/src/github /usr/src/scan_results /root/.gf /root/nuclei-templates \
    && wget -q https://raw.githubusercontent.com/maurosoria/dirsearch/master/db/dicc.txt -O /usr/src/wordlist/dicc.txt \
    && wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/deepmagic.com-prefixes-top50000.txt -O /usr/src/wordlist/deepmagic.com-prefixes-top50000.txt

RUN git clone --depth 1 https://github.com/aboul3la/Sublist3r /usr/src/github/Sublist3r \
    && git clone --depth 1 https://github.com/shmilylty/OneForAll /usr/src/github/OneForAll \
    && git clone --depth 1 https://github.com/FortyNorthSecurity/EyeWitness /usr/src/github/EyeWitness \
    && git clone --depth 1 https://github.com/laramies/theHarvester /usr/src/github/theHarvester \
    && git clone --depth 1 https://github.com/scipag/vulscan /usr/src/github/scipag_vulscan \
    && ln -s /usr/src/github/scipag_vulscan /usr/share/nmap/scripts/vulscan \
    && git clone --depth 1 https://github.com/Tuhinshubhra/CMSeeK /usr/src/github/CMSeeK \
    && git clone --depth 1 https://github.com/UnaPibaGeek/ctfr /usr/src/github/ctfr \
    && git clone --depth 1 https://github.com/m3n0sd0n4ld/GooFuzz.git /usr/src/github/goofuzz \
    && chmod +x /usr/src/github/goofuzz/GooFuzz \
    && pip3 install --no-cache-dir -r /usr/src/github/Sublist3r/requirements.txt \
        -r /usr/src/github/OneForAll/requirements.txt \
        -r /usr/src/github/theHarvester/requirements/base.txt \
        -r /usr/src/github/CMSeeK/requirements.txt \
        h8mail tenacity==8.2.2

RUN cp -r $GOPATH/src/github.com/tomnomnom/gf/examples/*.json /root/.gf/ 2>/dev/null || true \
    && git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns /tmp/gfp && mv /tmp/gfp/*.json /root/.gf/ && rm -rf /tmp/gfp \
    && git clone --depth 1 https://github.com/geeknik/the-nuclei-templates.git /root/nuclei-templates/geeknik_nuclei_templates \
    && wget -q https://raw.githubusercontent.com/NagliNagli/BountyTricks/main/ssrf.yaml -O /root/nuclei-templates/ssrf_nagli.yaml
```
Run: `docker compose -p limes-test -f docker-compose.test.yml build test`
Expected: build succeeds.

- [ ] **Step 4: Rewrite the entrypoints**

`web/migrate-entrypoint.sh`:
```bash
#!/bin/bash
set -euo pipefail
python3 manage.py migrate --noinput
python3 manage.py collectstatic --no-input --clear
python3 manage.py loaddata fixtures/default_scan_engines.yaml --app scanEngine.EngineType
python3 manage.py loaddata fixtures/default_keywords.yaml --app scanEngine.InterestingLookupModel
python3 manage.py loaddata fixtures/external_tools.yaml --app scanEngine.InstalledExternalTool
```

`web/entrypoint.sh`:
```bash
#!/bin/bash
set -euo pipefail
eval "$(python3 /usr/src/app/limes/sizing.py)"
exec gunicorn limes.wsgi:application \
    --bind 0.0.0.0:8000 \
    --workers "${WEB_WORKERS}" --worker-class gthread --threads 4 \
    --timeout 300 --access-logfile - --error-logfile -
```

`web/celery-entrypoint.sh`:
```bash
#!/bin/bash
set -euo pipefail
eval "$(python3 /usr/src/app/limes/sizing.py)"
loglevel=info
[ "${DEBUG:-0}" = "1" ] && loglevel=debug
role="${1:?usage: celery-entrypoint.sh scan|io|orchestrate}"
case "$role" in
  scan)
    exec celery -A limes.celery worker -Q scan -n "scan@${HOSTNAME}" -P prefork -O fair \
      --prefetch-multiplier=1 --max-tasks-per-child=20 --autoscale="${SCAN_SLOTS},1" -l "$loglevel" ;;
  io)
    export CELERY_POOL=gevent
    exec celery -A limes.celery worker -Q io -n "io@${HOSTNAME}" -P gevent -c "${IO_CONCURRENCY}" -l "$loglevel" ;;
  orchestrate)
    exec celery -A limes.celery worker -Q orchestrate -n "orchestrate@${HOSTNAME}" -P prefork -c 2 -l "$loglevel" ;;
  *) echo "unknown role $role" >&2; exit 2 ;;
esac
```

`web/beat-entrypoint.sh`:
```bash
#!/bin/bash
set -euo pipefail
exec celery -A limes.celery beat -l info --scheduler django_celery_beat.schedulers:DatabaseScheduler
```
Run: `chmod +x web/*.sh`

- [ ] **Step 5: Rewrite `docker-compose.yml`**

```yaml
x-app: &app
  build:
    context: ./web
  image: limes-next:local
  restart: unless-stopped
  env_file: .env
  environment: &app-env
    DEBUG: "0"
    CELERY_BROKER: redis://redis:6379/0
    CACHE_URL: redis://redis:6379/1
    POSTGRES_HOST: pgbouncer
    POSTGRES_PORT: "6432"
  volumes: &app-volumes
    - wordlist:/usr/src/wordlist
    - scan_results:/usr/src/scan_results
    - nuclei_templates:/root/nuclei-templates
    - tool_config:/root/.config
  networks: [limes_network]
  depends_on: &app-deps
    migrate:
      condition: service_completed_successfully
    pgbouncer:
      condition: service_started
    redis:
      condition: service_healthy

x-worker-health: &worker-health
  interval: 60s
  timeout: 30s
  retries: 3
  start_period: 60s

services:
  db:
    image: "postgres:12.3-alpine"
    restart: unless-stopped
    environment:
      - POSTGRES_DB=${POSTGRES_DB}
      - POSTGRES_USER=${POSTGRES_USER}
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
    command: ["postgres", "-c", "max_connections=${PG_MAX_CONNECTIONS:-100}"]
    volumes:
      - postgres_data:/var/lib/postgresql/data/
    networks: [limes_network]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U $${POSTGRES_USER} -d $${POSTGRES_DB}"]
      interval: 10s
      retries: 10

  redis:
    image: "redis:7.2-alpine"
    restart: unless-stopped
    command: ["redis-server", "--maxmemory", "${REDIS_MAXMEMORY:-512mb}", "--maxmemory-policy", "noeviction", "--appendonly", "yes"]
    volumes:
      - redis_data:/data
    networks: [limes_network]
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      retries: 10

  pgbouncer:
    image: "edoburu/pgbouncer:${PGBOUNCER_TAG:?set PGBOUNCER_TAG in .env}"
    restart: unless-stopped
    environment:
      - DB_HOST=db
      - DB_PORT=5432
      - DB_USER=${POSTGRES_USER}
      - DB_PASSWORD=${POSTGRES_PASSWORD}
      - DB_NAME=${POSTGRES_DB}
      - POOL_MODE=transaction
      - DEFAULT_POOL_SIZE=${DB_POOL_SIZE:-40}
      - MAX_CLIENT_CONN=1000
      - AUTH_TYPE=md5
      - LISTEN_PORT=6432
    depends_on:
      db:
        condition: service_healthy
    networks: [limes_network]

  migrate:
    <<: *app
    restart: "no"
    entrypoint: /usr/src/app/migrate-entrypoint.sh
    environment:
      <<: *app-env
      POSTGRES_HOST: db
      POSTGRES_PORT: "5432"
    volumes:
      - static_volume:/usr/src/app/staticfiles/
    depends_on:
      db:
        condition: service_healthy

  web:
    <<: *app
    entrypoint: /usr/src/app/entrypoint.sh
    mem_limit: ${WEB_MEM:-2g}
    environment:
      <<: *app-env
      DOMAIN_NAME: ${DOMAIN_NAME}
    volumes:
      - scan_results:/usr/src/scan_results
      - static_volume:/usr/src/app/staticfiles/
    networks:
      limes_network:
        aliases: [limes]
    healthcheck:
      test: ["CMD", "python3", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=5)"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 30s

  worker-scan:
    <<: *app
    entrypoint: ["/usr/src/app/celery-entrypoint.sh", "scan"]
    mem_limit: ${WORKER_SCAN_MEM:-8g}
    healthcheck:
      <<: *worker-health
      test: ["CMD-SHELL", "celery -A limes.celery inspect ping -d scan@$${HOSTNAME} -t 20"]

  worker-io:
    <<: *app
    entrypoint: ["/usr/src/app/celery-entrypoint.sh", "io"]
    mem_limit: ${WORKER_IO_MEM:-2g}
    healthcheck:
      <<: *worker-health
      test: ["CMD-SHELL", "celery -A limes.celery inspect ping -d io@$${HOSTNAME} -t 20"]

  worker-orch:
    <<: *app
    entrypoint: ["/usr/src/app/celery-entrypoint.sh", "orchestrate"]
    mem_limit: ${WORKER_ORCH_MEM:-1g}
    healthcheck:
      <<: *worker-health
      test: ["CMD-SHELL", "celery -A limes.celery inspect ping -d orchestrate@$${HOSTNAME} -t 20"]

  beat:
    <<: *app
    entrypoint: /usr/src/app/beat-entrypoint.sh
    mem_limit: 512m

  proxy:
    image: nginx:1.27-alpine
    restart: unless-stopped
    ports:
      - 8082:8082/tcp
      - 443:443/tcp
    depends_on:
      web:
        condition: service_healthy
    secrets:
      - source: proxy.ca
        target: /etc/nginx/certs/limes_chain.pem
      - source: proxy.cert
        target: /etc/nginx/certs/limes.pem
      - source: proxy.key
        target: /etc/nginx/certs/limes_rsa.key
    volumes:
      - ./config/nginx/limes.conf:/etc/nginx/conf.d/limes.conf:ro
      - static_volume:/usr/src/app/staticfiles/
      - scan_results:/usr/src/scan_results
    networks: [limes_network]

  ollama:
    image: ollama/ollama
    restart: unless-stopped
    volumes:
      - ollama_data:/root/.ollama
    networks: [limes_network]

networks:
  limes_network:

volumes:
  tool_config:
  postgres_data:
  redis_data:
  nuclei_templates:
  wordlist:
  scan_results:
  static_volume:
  ollama_data:

secrets:
  proxy.ca:
    file: ./secrets/certs/limes_chain.pem
  proxy.key:
    file: ./secrets/certs/limes_rsa.key
  proxy.cert:
    file: ./secrets/certs/limes.pem
```
Pin pgbouncer: look up the current release tag of `edoburu/pgbouncer` on Docker Hub (not `latest`), confirm it pulls with `docker pull edoburu/pgbouncer:<tag>`, and add `PGBOUNCER_TAG=<tag>` to your local `.env` now (Task 12 adds it to `.env.example`).

`docker-compose.dev.yml` (override, used as `-f docker-compose.yml -f docker-compose.dev.yml`):
```yaml
x-dev: &dev
  environment:
    DEBUG: "1"
  volumes:
    - ./web:/usr/src/app

services:
  web:
    <<: *dev
    ports:
      - "127.0.0.1:8000:8000"
  worker-scan: *dev
  worker-io: *dev
  worker-orch: *dev
  beat: *dev
  migrate: *dev
  db:
    ports:
      - "127.0.0.1:5432:5432"
```
Note: merging `volumes` in an override appends to the base list, so the named volumes stay mounted.

`Makefile`: set `SERVICES := db redis pgbouncer migrate web worker-scan worker-io worker-orch beat proxy ollama`.

- [ ] **Step 6: Validate and bring the stack up**

Run:
```bash
docker compose config -q && echo compose-ok
make build && make up
docker compose ps --format 'table {{.Name}}\t{{.Status}}'
```
Expected: `compose-ok`; `migrate` exited 0; `web`, `worker-scan`, `worker-io`, `worker-orch` report `(healthy)` within 2 minutes; `ollama` has no published port.

- [ ] **Step 7: Restart-on-death check**

Run:
```bash
docker compose exec worker-io sh -c 'kill 1'
sleep 20 && docker compose ps worker-io
curl -sk https://localhost/healthz
```
Expected: `worker-io` is `Up` again (restarted); healthz prints `{"status": "ok"}`.

- [ ] **Step 8: Run tests** — `make test`, all PASS.

- [ ] **Step 9: Commit**

```bash
git add docker-compose.yml docker-compose.dev.yml Makefile web/Dockerfile web/entrypoint.sh web/celery-entrypoint.sh web/beat-entrypoint.sh web/migrate-entrypoint.sh web/limes/health.py web/limes/urls.py web/limes/settings.py web/tests/core/test_health.py
git commit -m "feat: split workers into restartable sized services behind pgbouncer

One container ran 21 backgrounded workers, so a crashed worker silently
stopped its queue; startup also installed tools and generated migrations
on every boot, and Django ran on the development server."
```

---

### Task 12: Secrets out of git, host-sized defaults

**Files:**
- Create: `.env.example`, `scripts/gen_env.py`, `scripts/test_gen_env.py`
- Modify: `.gitignore`, `install.sh:16-40`
- Remove from index: `.env`

**Interfaces:**
- Produces: `python3 scripts/gen_env.py [--out .env] [--example .env.example]` — writes `.env` from the example with fresh random secrets and host-sized limits; refuses to overwrite an existing file.

- [ ] **Step 1: Write failing tests**

`scripts/test_gen_env.py`:
```python
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
EXAMPLE = os.path.join(HERE, '..', '.env.example')


class GenEnvTest(unittest.TestCase):
    def run_gen(self, out):
        return subprocess.run([sys.executable, os.path.join(HERE, 'gen_env.py'), '--out', out, '--example', EXAMPLE],
                              capture_output=True, text=True)

    def parse(self, path):
        with open(path) as f:
            return dict(line.strip().split('=', 1) for line in f if '=' in line and not line.startswith('#'))

    def test_generates_unique_secrets(self):
        d = tempfile.mkdtemp()
        a, b = os.path.join(d, 'a'), os.path.join(d, 'b')
        self.assertEqual(self.run_gen(a).returncode, 0)
        self.assertEqual(self.run_gen(b).returncode, 0)
        ea, eb = self.parse(a), self.parse(b)
        for key in ('POSTGRES_PASSWORD', 'DJANGO_SUPERUSER_PASSWORD', 'LIMES_SECRET_KEY', 'AUTHORITY_PASSWORD'):
            self.assertGreaterEqual(len(ea[key]), 32, key)
            self.assertNotEqual(ea[key], eb[key], key)
            self.assertNotIn('CHANGE_ME', ea[key])
        self.assertEqual(os.stat(a).st_mode & 0o777, 0o600)

    def test_sizes_from_host(self):
        d = tempfile.mkdtemp()
        out = os.path.join(d, 'e')
        self.run_gen(out)
        env = self.parse(out)
        self.assertRegex(env['WORKER_SCAN_MEM'], r'^\d+g$')

    def test_refuses_to_overwrite(self):
        d = tempfile.mkdtemp()
        out = os.path.join(d, 'e')
        open(out, 'w').close()
        self.assertNotEqual(self.run_gen(out).returncode, 0)


if __name__ == '__main__':
    unittest.main()
```
Run: `python3 -m unittest scripts/test_gen_env.py -v` → fails (missing files).

- [ ] **Step 2: Create `.env.example`**

```bash
COMPOSE_PROJECT_NAME=limes

# Certificate authority (used by `make certs`)
AUTHORITY_NAME=Limes
AUTHORITY_PASSWORD=CHANGE_ME
COMPANY=Limes
DOMAIN_NAME=limes.example.com
COUNTRY_CODE=US
STATE=Georgia
CITY=Atlanta

# Database
POSTGRES_DB=limes
POSTGRES_USER=limes
POSTGRES_PASSWORD=CHANGE_ME
POSTGRES_PORT=5432
POSTGRES_HOST=db
PG_MAX_CONNECTIONS=100
DB_POOL_SIZE=40
PGBOUNCER_TAG=SET_ME

# Django
LIMES_SECRET_KEY=CHANGE_ME
DJANGO_SUPERUSER_USERNAME=limes
DJANGO_SUPERUSER_EMAIL=limes@example.com
DJANGO_SUPERUSER_PASSWORD=CHANGE_ME

# Sizing (gen_env.py fills these from the host; leave empty to auto-size inside containers)
REDIS_MAXMEMORY=512mb
WORKER_SCAN_MEM=8g
WORKER_IO_MEM=2g
WORKER_ORCH_MEM=1g
WEB_MEM=2g
SCAN_SLOTS=
IO_CONCURRENCY=
WEB_WORKERS=
```
Set `PGBOUNCER_TAG` to the tag pinned in Task 11 Step 5.

- [ ] **Step 3: Implement `scripts/gen_env.py`**

```python
"""Create .env from .env.example with fresh secrets and memory limits sized to this host."""
import argparse
import os
import secrets
import sys

SECRET_KEYS = ('AUTHORITY_PASSWORD', 'POSTGRES_PASSWORD', 'DJANGO_SUPERUSER_PASSWORD', 'LIMES_SECRET_KEY')


def host_mem_gib():
    with open('/proc/meminfo') as f:
        for line in f:
            if line.startswith('MemTotal:'):
                return int(line.split()[1]) // (1024 * 1024)
    return 8


def sized(mem_gib):
    usable = max(4, mem_gib - 2)
    scan = max(2, int(usable * 0.6))
    io = max(1, int(usable * 0.15))
    web = max(1, int(usable * 0.1))
    return {'WORKER_SCAN_MEM': f'{scan}g', 'WORKER_IO_MEM': f'{io}g', 'WEB_MEM': f'{web}g',
            'WORKER_ORCH_MEM': '1g', 'REDIS_MAXMEMORY': f'{max(256, int(usable * 1024 * 0.05))}mb'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', default='.env')
    parser.add_argument('--example', default='.env.example')
    args = parser.parse_args()
    if os.path.exists(args.out):
        sys.exit(f'{args.out} already exists; refusing to overwrite')
    values = {key: secrets.token_urlsafe(32) for key in SECRET_KEYS}
    values.update(sized(host_mem_gib()))
    lines = []
    with open(args.example) as f:
        for line in f:
            key = line.split('=', 1)[0]
            if '=' in line and not line.startswith('#') and key in values:
                line = f'{key}={values[key]}\n'
            lines.append(line)
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.writelines(lines)
    print(f'wrote {args.out}')


if __name__ == '__main__':
    main()
```
Run: `python3 -m unittest scripts/test_gen_env.py -v` → 3 tests PASS.

- [ ] **Step 4: Stop tracking `.env`**

```bash
printf '\n# Local environment (generated by scripts/gen_env.py)\n.env\n' >> .gitignore
git rm --cached .env
```
The local `.env` file stays on disk; only git stops tracking it.

- [ ] **Step 5: Installer uses the generator** — in `install.sh`, replace the block that asks "Are you sure, you made changes to .env file" (lines ≈ 16-40) with:
```bash
if [ ! -f .env ]; then
  python3 scripts/gen_env.py --out .env --example .env.example || exit 1
  tput setaf 2; echo "Generated .env with random secrets and host-sized limits. Review it before continuing."
fi
```
Run: `bash -n install.sh && echo syntax-ok`

- [ ] **Step 6: Commit**

```bash
git add .env.example .gitignore install.sh scripts/gen_env.py scripts/test_gen_env.py
git commit -m "fix: stop tracking .env and generate secrets at install

The tracked .env shipped publicly known default passwords; deployments
that kept them must rotate them."
```
Confirm with `git status --short` that `.env` shows as deleted from the index (`D  .env` before commit) and is not re-added.

---

### Task 13: After-benchmark and done check

**Files:**
- Create: `docs/benchmarks/2026-10-phase0a-after.md`

- [ ] **Step 1: Re-run the benchmark on the new stack** (same host as the baseline)

```bash
make up
make bench-seed
make bench-dashboard > /tmp/dash.txt
make bench-scans > /tmp/scans.txt
docker stats --no-stream --format '{{.Name}} {{.MemUsage}}' > /tmp/mem.txt
docker image ls --format '{{.Repository}}:{{.Tag}} {{.Size}}' | grep -i limes > /tmp/img.txt
```

- [ ] **Step 2: Check the 0A exit criteria**

- Dashboard warm p95 < 500 ms and cold query count ≤ 25 (from `/tmp/dash.txt`).
- `stuck=0` in `/tmp/scans.txt`.
- `make test` all PASS; `python3 -m unittest scripts/test_gen_env.py` PASS.
- `make manage ARGS="makemigrations --check --dry-run"` → `No changes detected`.

If any criterion fails, stop and investigate with superpowers:systematic-debugging before changing code.

- [ ] **Step 3: Write `docs/benchmarks/2026-10-phase0a-after.md`** with the commit hash, host info, the four outputs verbatim, and a before/after table (dashboard p50/p95 cold and warm, query count, stuck scans, total memory, image size) referencing the baseline file.

- [ ] **Step 4: Commit**

```bash
git add docs/benchmarks/2026-10-phase0a-after.md
git commit -m "docs: record phase 0A benchmark results"
```
