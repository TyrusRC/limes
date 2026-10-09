# ASM module — Slice A3b: Passive providers (crt.sh, Shodan InternetDB, RIPEstat)

Status: design approved in brainstorming 2026-10-09; awaits user review of this file before planning.
Parent: Limes ASM platform. Builds on A3a (dnsx resolution + fail-closed scope guard, merged `c6a0cf8`).
Spec basis: `docs/superpowers/specs/2026-10-07-asm-platform-roadmap-design.md` ("Free: ransomware.live leak-site mentions, Shodan InternetDB, RIPEstat, crt.sh"; Scope tiers: Candidate = "passive enrichment only, review queue"; Rejected = "remembered so it is never re-suggested").
Platform: Django 3.2 + Celery 5.4 + PostgreSQL, internal package `limes`.

## Module context

ASM slices: A0 ✓ · A1 ✓ · A2 ✓ · A3a ✓ · **A3b this slice** · A3c attack-surface graph + ownership confidence · A4 risk scoring · A5 continuous.

## Goal

Find more of the organization's attack surface and enrich what is already known, using three free, keyless, passive sources — without sending a single packet to any target. Anything not provably under an owned root becomes a **candidate** in the existing Confirm/Reject queue (A2), never an owned asset.

## Findings that shape the design

- subfinder already queries crt.sh as one of its passive sources, so crt.sh's unique value here is **certificate co-tenancy**: other registrable domains listed on the same certificates as an owned root.
- `tldextract` downloads the public-suffix list on first use. Every registrable-domain decision in this slice uses `tldextract.TLDExtract(suffix_list_urls=())` (bundled snapshot, no network).

## Scope

**In:** provider clients for crt.sh, Shodan InternetDB and RIPEstat; a `passive_intel` Celery stage after discovery in `asm` and `full` modes; `Asset.enrichment`; `inventory.upsert_candidate`; enrichment shown in the asset detail modal; a README section listing the providers and InternetDB's non-commercial terms.

**Out (later slices):** using ASN/prefix/holder or certificate evidence for ownership confidence and auto-confirmation (A3c); ransomware.live and paid providers; periodic runs outside scans (A5); provider API keys.

## Design

### 1. Provider modules (`web/limes/intel/`)

Each module is pure (no Django, no network) and mirrors `limes/pipeline/amass.py`:

- `crtsh.py`: `build_url(root) -> str` (`https://crt.sh/?q=%25.<root>&output=json&exclude=expired`); `parse(rows) -> list[{'id': int, 'names': list[str]}]` — splits `name_value` on newlines, lower-cases, strips `*.` and trailing dots, drops non-domains.
- `internetdb.py`: `build_url(ip) -> str` (`https://internetdb.shodan.io/<ip>`); `parse(obj) -> {'ports': [int], 'cpes': [str], 'vulns': [str], 'tags': [str], 'hostnames': [str]}`; a 404 body (`{"detail": ...}`) parses to `None` (no data).
- `ripestat.py`: `network_info_url(ip)`, `as_overview_url(asn)` (both with `sourceapp=limes`); `parse_network_info(obj) -> {'asn': str|None, 'prefix': str|None}`; `parse_as_overview(obj) -> {'holder': str|None}`.
- `http.py`: `get_json(url, *, provider) -> (status, obj|None)` — `requests.get` with `timeout=30`, header `User-Agent: Limes-ASM`, up to 2 retries with exponential backoff on 429/5xx/connection errors, and a per-provider minimum interval between requests (crt.sh 5 s, InternetDB 1 s, RIPEstat 0.25 s) enforced with an injectable clock/sleep. Never raises: failures return `(None, None)` and are logged.
- `domains.py`: `registrable(name) -> str|None` via the offline `TLDExtract`.

### 2. What each provider produces

- **crt.sh** — per owned root of the scan (`owned_root` root_domain asset):
  - names whose registrable domain equals the root → `inventory.upsert_hostname_asset(project, name, parent=root, source='crtsh', evidence=f'cert:{id}')` (same rule as every discovery source);
  - other registrable domains on the same certificate → `upsert_candidate(project, 'root_domain', domain, source='crtsh', evidence=f'cert:{id} shared with {root}')`;
  - certificates listing more than 20 distinct registrable domains are skipped for candidates (mass-shared CDN certificates are not ownership evidence);
  - at most 10 000 names per root are processed (NOTE naming the ceiling).
- **Shodan InternetDB** — per IP asset linked to the root's hosts (owned and dependency), skipping IPs whose `enrichment['internetdb']['fetched_at']` is under 24 h old:
  - `Asset.enrichment['internetdb'] = {ports, cpes, vulns, tags, hostnames, fetched_at}` (on a 404, `{'fetched_at': ..., 'no_data': True}`);
  - hostnames found on **owned** IPs (`owned_root`/`owned_host`) whose registrable domain is not an owned root → candidate `root_domain` (evidence `ip:<ip>`); hostnames on dependency IPs are ignored (CDN IPs list unrelated sites).
- **RIPEstat** — per IP asset, same 24 h skip: `Asset.enrichment['ripestat'] = {asn, prefix, holder, fetched_at}`. No candidates.

### 3. Inventory rules (`limes/tasks/inventory.py`, `startScan/asset_models.py`)

- New `Asset.enrichment = JSONField(default=dict, blank=True)` (migration `startScan/0014_asset_enrichment`).
- `upsert_candidate(project, kind, value, source, evidence)`: creates the asset as `candidate`; for an existing asset of any tier, only appends the source/evidence — never changes `scope_tier` (an owned asset stays owned; a **rejected** one stays rejected and is never re-suggested).
- Values are normalized with `normalize_host`; candidates that equal an existing owned root or fall under one are not created as candidates.

### 4. Stage (`limes/tasks/stages.py`, `limes/tasks/control.py`, `limes/celery_routing.py`)

- New task `passive_intel(ctx)` (`name='passive_intel'`, `base=LimesTask`): finds the root with a new `resolution.root_for_domain(domain) -> (project, root)` helper (the lookup `resolve_domain` does today, extracted and reused by it); the stage proceeds only when the root's `scope_tier` is `owned_root` — a candidate or rejected root is never expanded; runs crt.sh, then re-resolves the root (`resolution.resolve_domain`) so the scope guard and per-IP enrichment see the hostnames crt.sh added; same-run active stages take targets from the scan's own discovery results, not from crt.sh, then InternetDB and RIPEstat over the root's IP assets. Each provider is wrapped so one failing provider never stops the others; the stage never raises.
- Workflow: `asm` = discovery → **passive_intel** → screenshot; `full` = discovery → **passive_intel** → port scan → fetch_url → (vuln, screenshot, code audit).
- `TASK_PLAN['passive_intel'] = (SCAN, 1 * HOUR)`; `inventory.STAGE_BY_TASK['passive_intel'] = 'discovery'`.
- The stage contacts only crt.sh, internetdb.shodan.io and stat.ripe.net — never a target — so it needs no scope guard; this is stated in the task docstring.
- Notify fields: counts of new hostnames, new candidates, IPs enriched, provider failures.

### 5. UI (`api/serializers.py`, `static/custom/asset.js`)

- `AssetSerializer` gains `enrichment`.
- The detail modal shows an "Intel" section: open ports, CPEs, vuln IDs, tags (InternetDB) and ASN / prefix / holder (RIPEstat), each with its fetch date; all values rendered through `asset_esc`.

## Data flow

discovery → `passive_intel`: crt.sh(root) → hostnames (owned_host under root) + candidate roots (co-tenancy) → `resolve_domain` → InternetDB/RIPEstat(root's IPs) → `enrichment` + candidate roots (hostnames on owned IPs) → later stages (guarded by A3a).

## Testing

- Parsers: fixtures for each provider (`tests/core/fixtures/crtsh_sample.json`, `internetdb_sample.json`, `internetdb_404.json`, `ripestat_network_info.json`, `ripestat_as_overview.json`) — wildcards, multi-line SANs, malformed rows, missing keys.
- `http.get_json`: fake transport + fake clock: rate interval respected per provider, retries with backoff on 429/503 then success, gives up after 2 retries, never raises on connection errors, timeout passed.
- `registrable`: offline (patch `requests` to fail; must still work), `example.co.uk`, IDN.
- Inventory: `upsert_candidate` creates candidate; existing owned/rejected tiers unchanged; candidate under an owned root not created.
- Stage (providers mocked at the `get_json` boundary): crt.sh co-tenancy → candidate; >20-domain certificate skipped; hostnames under root become owned_host; InternetDB hostnames on owned IP → candidate, on dependency IP → ignored; 24 h skip; one provider failing leaves the others' results; workflow chains include `passive_intel` in the right position.
- No test touches the network.

## Review focus

1. **Never a packet to a target** — only the three provider hosts are contacted.
2. **Rejected stays rejected** — no provider path re-suggests or changes a decided asset.
3. **No network in registrable-domain decisions** (offline PSL).
4. **Politeness** — rate limits and timeouts on every provider call; failures never break the scan.
5. **Noise control** — mass-shared certificates and CDN IP hostnames do not flood the candidate queue.

## Risks

- **Provider availability** — crt.sh is frequently slow or down; the stage degrades to fewer results, logged and counted. NOTE in `http.py`: upgrade path to a local CT mirror / certstream (roadmap).
- **ToS** — InternetDB is free for non-commercial use per Shodan's terms; operators deploying commercially must check it. Stated in the README's provider section.
- **Queue growth** — co-tenancy on large organizations can produce many candidates; the 20-domain certificate cap and the per-root cap bound it.
