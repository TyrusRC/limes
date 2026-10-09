# ASM module — Slice A3a: DNS resolve stage + IP scope guard

Status: design approved in brainstorming 2026-10-09; awaits user review of this file before planning.
Parent: Limes ASM platform. Builds on A1 (pipeline → inventory) and A2 (inventory UI/API).
Spec basis: `docs/superpowers/specs/2026-10-07-asm-platform-roadmap-design.md` (Scope tiers: "Shared CDN / SaaS / cloud IPs are Dependency nodes and are never scanned by IP. The scope check runs at every active stage"), `docs/superpowers/specs/2026-10-08-asm-module-a1-pipeline-inventory-design.md` (A3 = discovery depth + graph).
Platform: Django 3.2 + Celery 5.4 + PostgreSQL, internal package `limes`/`startScan`/`api`.

## Module context

ASM slices: A0 inventory ✓ · A1 pipeline→inventory ✓ · A2 inventory UI/API ✓ · **A3a this slice** · A3b passive providers (crt.sh, Shodan InternetDB, RIPEstat → candidates) · A3c attack-surface graph + ownership confidence · A4 risk scoring · A5 continuous. A3 was split because A3b and A3c both need resolved hosts and a trustworthy scope boundary first.

## Problem (found in code, 2026-10-09)

1. **No DNS state for non-HTTP hosts.** Host IPs/CNAME only arrive through httpx (`http_crawl` → `save_subdomain` → `upsert_ip_asset`). A discovered name with no web server has no resolution at all. `dnsx` is installed in the image but nothing calls it.
2. **Resolved IPs are auto-owned.** `limes/tasks/inventory.py:upsert_ip_asset` creates every IP an owned host resolves to as `scope_tier='owned_host'`, so shared CDN / SaaS / cloud IPs become "ours" and active-scannable by IP.
3. **The scope check is never enforced.** `inventory.is_active_scan_allowed_for` exists but no stage calls it. In `full`/`scanner` mode, port scan, crawl, DAST and SAST run on every discovered host regardless of tier, and nothing stops traffic to hosts that resolve to private/reserved IPs (e.g. `10.0.0.1.nip.io`).

## Goal

Every discovered host is resolved; resolved IPs are recorded without being presumed owned; and every stage that sends traffic checks scope first and fails closed.

## Scope

**In:**
- A `resolve` Celery stage running dnsx (A, AAAA, CNAME) over the run's hosts, in every scan mode.
- A new scope tier `dependency` and IP-ownership inference on upsert.
- A data migration demoting previously auto-owned IP assets to `dependency`.
- `limes/scope.py`: the shared reserved-range definition and two guard levels, called at the start of every traffic-sending stage.

**Out (later slices):** CT logs / passive DNS / provider pivots (A3b); graph edge tables, confidence decay, review-queue automation (A3c); pinning tools to resolved IPs (see Risks); UI changes beyond the new tier appearing in the existing Assets filters and badges.

## Design

### 1. Resolve stage (`limes/tasks/stages.py`, `limes/pipeline/dnsx.py`)

- `limes/pipeline/dnsx.py` (pure, mirrors `limes/pipeline/amass.py`): `build_argv(hosts_file, output_file)` returns an argv list (`dnsx -l <hosts_file> -a -aaaa -cname -resp -json -silent -o <output_file>`), and `parse(lines)` returns `{host: {'a': [...], 'aaaa': [...], 'cname': [...]}}`, skipping malformed lines and lower-casing/normalizing hosts with `normalize_host`.
- New task `resolve(ctx)` (`name='resolve'`, `base=LimesTask`): writes the run's hostname assets under the root (`Asset.objects.filter(project, kind='hostname', parent=run.root_asset)`) to a file, runs dnsx via `commands.run` (argv, never `shell=True`), parses the output and for each host:
  - sets `cname` via `inventory.update_host_state`;
  - for each A/AAAA address calls `inventory.upsert_ip_asset(project, address, source='dns', evidence=f'host:{name}')` and links it on the host's `ip_addresses` (`IpAddress` get_or_create, as `persistence.save_ip_address` does today);
  - records `last_resolved_at` on the host asset (new nullable field).
- Hosts dnsx did not answer keep their previous IPs; `last_resolved_at` is not updated. A dnsx failure is logged and the run continues (resolution is best-effort; the guard fails closed on missing data).
- Workflow (`control.build_workflow`): `asm` = discovery → **resolve** → screenshot; `full`/`scanner` = discovery → **resolve** → port scan → fetch_url → (vuln, screenshot, code audit). `resolve` is added to `celery_routing.TASK_PLAN` as `(SCAN, 1 * HOUR)`: it runs an external tool, like every other stage (the `io` gevent pool is for short parse/notify work).

### 2. IP ownership (`limes/tasks/inventory.py`, `startScan/asset_models.py`)

- `SCOPE_TIERS` gains `dependency` ("observed infrastructure we rely on but do not own; never scanned by IP"). Choices-only `AlterField` migration `startScan/0011_asset_dependency_tier`.
- `upsert_ip_asset(project, address, source, evidence)`:
  - new IP inside an owned `ip`/`cidr` asset of the same project (`ipaddress` containment over `Asset(kind in ('ip','cidr'), scope_tier in ('owned_root','owned_host'))`) → `owned_host`; otherwise → `dependency`;
  - existing IP: tier is never changed by upsert (no downgrade of a human or CIDR decision, no promotion of a dependency) — only `sources`/`last_seen` update;
  - reserved/private addresses (per `scope.is_reserved_ip`) are still recorded (they are evidence of misconfiguration) but always as `dependency`.
- Data migration `startScan/0012_demote_auto_owned_ips` (after `0011`, the `dependency` choices change): for `kind='ip'`, `scope_tier='owned_host'`, `added_by IS NULL`, `decision_reason` empty, every `sources` entry with `source` in (`probe`, `dns`), and not inside an owned `cidr`/`ip` asset of its project → `dependency`. Reverse is a no-op (cannot know which were genuinely owned).

### 3. Scope guard (`limes/scope.py`, new)

- `RESERVED_NETWORKS` and `is_reserved_ip(ip)` move here from `api/asset_add.py` (which imports them; behaviour unchanged, its tests keep passing). `is_reserved_ip` covers the IPv4-mapped collapse, `is_global`, multicast, and overlap with the reserved list.
- `may_contact(project, hosts) -> (allowed, refused)`: a hostname is allowed only if it has at least one resolved IP and **every** resolved IP is non-reserved; an IP target only if non-reserved. `refused` is a list of `(target, reason)`.
- `may_attack(project, hosts) -> (allowed, refused)`: `may_contact` **and** the target's asset `is_active_scan_allowed` (owned_root / owned_host / authorized co_brand). `dependency`, `candidate`, `rejected`, unknown targets are refused. IP targets are looked up as `kind='ip'` assets.
- Fail closed: missing asset, no resolution, or any exception in the check → refused with a reason.
- Called at the start of each stage that sends traffic, on that stage's own target list:
  - `may_contact`: `http_crawl` (httpx probe), `screenshot`.
  - `may_attack`: `port_scan`, `nmap`, `fetch_url`, `vulnerability_scan`, `code_audit`.
  - Stages that derive targets from the DB (`fetch_url`, `vulnerability_scan`, `code_audit`) filter after deriving, before invoking the tool.
- Refusals: `logger.warning` per target with the reason, and a `Refused (scope)` count field in the stage's existing `self.notify(...)`.
- `inventory.is_active_scan_allowed_for` is replaced by `scope.may_attack` (it had no callers).

## Data flow

discovery (names) → `save_subdomain` → hostname assets → **resolve** (dnsx) → IP assets (`dependency` unless inside owned CIDR) + host IPs/CNAME → **may_contact** gates httpx/screenshot → **may_attack** gates port/crawl/DAST/SAST.

## Testing

- `test_dnsx.py`: argv shape (no shell metacharacters reach a shell; list form), parser over a fixture (`tests/core/fixtures/dnsx_sample.jsonl`: A+AAAA+CNAME host, CNAME-only host, malformed line, mixed-case host).
- `test_scope.py`: `is_reserved_ip` table (moved cases from `test_asset_add` still pass there); `may_contact` refuses unresolved host, host with one private IP among public ones, `10.0.0.1.nip.io`-style host resolving to 10/8; `may_attack` refuses dependency / candidate / rejected / unauthorized co_brand / unknown, allows owned_root, owned_host, authorized co_brand; any exception → refused.
- `test_ip_ownership.py`: new IP inside owned CIDR → owned_host; outside → dependency; private → dependency; existing owned IP stays owned when re-upserted from dns; existing dependency stays dependency.
- Migration test: auto-owned probe IP demoted; IP with `added_by`, with a reason, or inside an owned CIDR untouched.
- Stage guard tests (one per guarded stage, `commands.run`/`run_command` mocked): a refused target never appears in the tool invocation; an allowed one does.
- Existing suites stay green; `makemigrations --check` clean after the two migrations.

## Review focus

1. **Fail closed everywhere** — no code path where a missing asset, missing resolution or exception lets a target through.
2. **Every traffic-sending stage is guarded** — grep for `run_command(` / `commands.run(` in stages; each must sit after a guard call.
3. **No promotion by upsert** — DNS evidence alone can never make an IP owned.
4. **Migration safety** — only machine-created, undecided IPs are demoted.
5. **argv only** — dnsx is never run through a shell.

## Risks

- **DNS rebinding / TOCTOU.** The guard checks the IPs from this run's resolve stage; a tool resolving later could get a different answer. NOTE in `scope.py` naming the ceiling; upgrade path: pass resolved IPs to tools (`naabu -host <ip>`, httpx `-resolvers` / host-to-IP pinning).
- **Scanning gets narrower on existing installs.** After the migration, CDN/SaaS IPs that were being port-scanned stop being scanned. This is the intended roadmap behaviour; release notes must say so.
- **Large roots.** One dnsx run per root; dnsx handles tens of thousands of names per minute. Hostname assets are streamed to the file with `.iterator()`.
