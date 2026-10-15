# ASM module — Slice A4: Explainable risk score

Status: design approved in brainstorming 2026-10-15; awaits user review of this file before planning.
Parent: Limes ASM platform. Builds on A5b (continuous rediscovery), `main` at `23146fd`.
Spec basis: `docs/superpowers/specs/2026-10-07-asm-platform-roadmap-design.md`:
- § "Score": an UpGuard-compatible 950-point model with published weights in versioned configuration; critical 200 / high 80 / medium 25 / low 5; a per-category cap; critical ceiling C and high ceiling B; a weakest-link roll-up with a P10 floor; daily snapshots with the model version, top penalties and coverage. Required invariant tests are merger invariance, monotonicity, immediate recovery on a verified fix, and waiver expiry.
- § "Noise control": banner CVEs are Unverified and visible only.

Platform: Django 3.2 + Celery 5.4 + PostgreSQL, internal package `limes`.

## Module context

ASM slices: A0–A3c ✓ · A5a ✓ · A5b ✓ · **A4 this slice** · A-dash dashboard redesign.

Waivers and false-positive disposition belong to roadmap sub-project 1, and the DNS, email and reputation checks to sub-project 4. Both are out of scope here.

## Goal

Every project gets a published, explainable 0–950 score and an A–F grade, built from the findings on its owned assets. Each asset shows its own score and the findings that cost points. A daily snapshot records the trend.

## Found in code (2026-10-15)

- **Findings are never linked to assets.** `Vulnerability.asset` exists (FK, `related_name='vulnerabilities'`), but no code sets it, so the Assets API's `vuln_count` is always 0.
- **One row per scan.** `save_vulnerability` does `get_or_create(**vuln_data)` including `scan_history`, so a finding found again by a later scan is a new row.
- **Severity codes** (`NUCLEI_SEVERITY_MAP`): critical 4, high 3, medium 2, low 1, info 0, unknown -1.
- **`ScanHistory.tasks` can't identify a baseline.** It is the engine's task list, and an `asm`-mode run of a full engine still lists `vulnerability_scan` without running it. Which stages actually ran is recorded in `ScanActivity` (`scan_of`, `name`, `status`).

## Decisions taken in brainstorming

- A4 is the score, plus the finding-to-asset link it needs.
- No waivers, no KEV/EPSS weighting, no InternetDB banner CVEs (they are visible only).
- **Project roll-up:** the 10th percentile of owned-asset scores.
- **Coverage** is shown next to the score.

## Scope

**In:**
- linking findings to assets (on write, plus a backfill command);
- `limes/scoring.py` (model `limes-score-v1`);
- the `ScoreSnapshot` model and a daily beat task;
- a project score API;
- per-asset score in the asset API;
- a score card on the Assets page, and a score section in the asset modal.

**Out:**
- waivers and false-positive marks;
- KEV/EPSS or crown-jewel priority;
- DNS, email, reputation and geo checks;
- issue grouping across assets;
- trend charts (snapshots are stored and exposed, but not charted);
- the dashboard.

## Design

### 1. Link findings to assets (`limes/tasks/persistence.py`)

`save_vulnerability` resolves the finding's host and sets `asset` before `get_or_create`:
- the host is `vuln_data['subdomain'].name` when present, else the hostname of `http_url`, lowercased and without its trailing dot;
- the asset is the project's `Asset` with `kind` in (`hostname`, `root_domain`) and `value == host`;
- the project is `vuln_data['scan_history'].domain.project`;
- if there is no match, `asset` stays null.

The function is shared by every finding writer (nuclei, DAST, nmap vulners), so they all get linked.

A management command, `link_vulnerabilities [project_slug]`, backfills `asset` for rows where it is null, using the same resolver (`resolve_vuln_asset(vuln) -> Asset | None`, exposed for reuse). It is idempotent and prints `linked=n`.

### 2. Score model (`limes/scoring.py`, `VERSION = 'limes-score-v1'`)

Constants, published in the module:

```
MAX_SCORE = 950
PENALTY = {4: 200, 3: 80, 2: 25, 1: 5}    # critical, high, medium, low; info/unknown 0
CEILING = {4: 599, 3: 799}                # any critical caps at C, any high at B
GRADES = [(800, 'A'), (600, 'B'), (400, 'C'), (200, 'D'), (0, 'F')]
COVERAGE_WINDOW = 30 days
```

**Scored assets:** the project's assets with `scope_tier` in (`owned_root`, `owned_host`), `kind` in (`root_domain`, `hostname`), and `state != 'retired'`.

**Baseline scan per root:** for each owned root's `Domain`, the latest `ScanHistory` that has a `ScanActivity` with `name='vulnerability_scan'` and `status=SUCCESS_TASK`.

**Counted findings:**
- `open_status` is true;
- `scan_history_id` is that domain's baseline;
- `asset` is a scored asset;
- `severity >= 1`.

A finding fixed and confirmed by a newer scan disappears from the newer baseline, so the score recovers immediately. Findings closed by hand (`open_status=False`) never count.

**Category:** `template_id`, else `name`. Per asset, each category counts **once**, at its highest severity. The same issue on 50 URLs is one penalty.

**Asset score:**
1. Start from `950 − Σ PENALTY[severity]` over the asset's categories, floored at 0.
2. Then `min(score, CEILING[s])` for the worst severity present.

An asset with no counted findings scores 950.

**Project score:**
- The nearest-rank 10th percentile of the scored assets' scores: sort ascending and take index `ceil(0.10 × n) − 1`, floored at index 0.
- With no scored assets the score is `None` and the grade is `'N/A'`.

**Grade:** the first band in `GRADES` whose threshold the score meets.

**Coverage:** owned roots with a baseline scan started within `COVERAGE_WINDOW`, divided by owned roots with a `Domain`. Returned as a ratio from 0 to 1, or `None` when there are no roots.

**Explanation:** `top_penalties` is the 5 largest `(asset value, category, severity, points)` entries in the project, largest first.

**API of the module:**
- `asset_breakdown(asset) -> {'score', 'grade', 'penalties': [...]}`;
- `project_score(project) -> {'version', 'score', 'grade', 'coverage', 'asset_count', 'top_penalties'}`.

Both are pure reads.

### 3. Snapshots (`startScan/asset_models.py`, next to `Asset` and `ScanRun`)

`ScoreSnapshot` fields:
- `project` FK;
- `date` (DateField);
- `version`;
- `score` (int, null);
- `grade`;
- `coverage` (float, null);
- `asset_count`;
- `top_penalties` (JSON);
- `unique_together (project, date)`.

The beat task `snapshot_scores` runs daily (`86400s`, `ORCHESTRATE` route). It upserts today's row per project with `update_or_create`, so re-running it on the same day overwrites rather than duplicates.

### 4. API

- `GET /api/asset_score/?project=<slug>` returns `project_score(project)` plus the last 30 snapshots (`date`, `score`, `grade`, `version`). It uses the same authentication as the Assets list. An unknown project returns 404.
- Asset retrieve (`/api/listDatatableAsset/<id>/`) adds `risk`, which is `asset_breakdown(asset)` for scored assets and `null` otherwise. List responses do not include it, which avoids N+1 scoring per page.

### 5. UI (`startScan/templates/startScan/assets.html`, `static/custom/asset.js`)

- **Score card** above the table:
  - large score and grade;
  - "Coverage NN% of owned roots scanned for vulnerabilities in 30 days";
  - the model version;
  - the top 5 penalties as rows of asset, issue, severity and points.
  - All values go through `asset_esc`. With no scored assets it says "No owned assets to score yet."
- **Modal:** a "Risk" section with the asset's score and grade and its penalty rows, or "No open findings in the latest vulnerability scan".

## Data flow

1. A scan's vulnerability stage calls `save_vulnerability`, which links each finding to its asset.
2. When the stage completes, its `ScanActivity` row is marked successful, and that scan becomes the domain's new baseline.
3. `project_score` and `asset_breakdown` read the baselines on demand.
4. `snapshot_scores` persists a daily row.

## Testing

**Linking:**
- a finding gets its hostname asset from `subdomain`, and from `http_url` when there is no subdomain;
- a root-level finding gets the root asset;
- another project's same-named asset is never linked;
- an unmatched host stays null;
- the backfill links old rows and is idempotent.

**Scoring invariants:**
- **Monotonicity:** adding a finding never raises an asset or project score.
- **Recovery:** a newer baseline without the finding restores 950, and an older scan's open row no longer counts.
- **Merger invariance:** duplicating a project's whole estate, so every asset score appears twice, leaves the project score unchanged.
- **Ceilings:** one critical caps at 599, and one high at 799 even with no other penalty.
- **Category cap:** the same template on 3 URLs is penalised once.
- **Baseline:** an `asm`-only scan (no `vulnerability_scan` activity), or a failed vulnerability stage, is never a baseline.
- **Exclusions:** retired, candidate and other non-owned assets, info/unknown severity, and `open_status=False` are never counted.

**Project roll-up:**
- P10 picks the expected index for n = 1, 9, 10 and 11;
- no assets gives `None` / `'N/A'`.

**Coverage:** a root scanned 29 days ago counts, and one scanned 31 days ago doesn't.

**Snapshot:** one row per project per day, and a re-run the same day updates it.

**API:**
- the score endpoint's shape;
- an unknown project returns 404;
- retrieve carries `risk` and list does not;
- authentication is required.

**UI:** drive the real Assets page: the card renders, the modal shows penalties, an XSS payload in a finding name renders as text, and there are no console errors.

## Review focus

1. **Double counting** across rescans, or across the same issue on many URLs. The baseline-scan selection and the per-category cap must both hold.
2. **A scan that skipped or failed the vulnerability stage** must not wipe findings by becoming the baseline. That would read as "all fixed".
3. **Finding-to-asset linking must never cross projects.**
4. **The P10 index at small n** (1, 2, 9, 10, 11) must be exact, and no assets must give N/A rather than a crash.
5. **Finding names, template ids and URLs** are scanner output, which means attacker-influenced text. They must be escaped everywhere they render.

## Risks

- **A scan that is only partially successful.** If the vulnerability stage succeeded on some hosts and timed out on others, it is still one successful activity and becomes the baseline. Missed hosts read as clean. Coverage shows only root-level freshness. The upgrade path is per-host baselines, using `ScanJob` per asset.
- **Hostnames without an asset.** Findings on hosts with no asset row stay unlinked and unscored. The pipeline upserts hostnames before the vulnerability stage, so this should be rare. The backfill command catches the stragglers.
- **P10 on tiny estates is close to the minimum.** With fewer than 10 assets, the project score equals the worst asset. That is intended: weakest link.

## Amendment after final review (2026-10-15)

- **A subscan's vulnerability stage never makes a baseline.** Subscans attach their `ScanActivity` to the parent scan but cover one host. Activities whose `celery_id` belongs to one of the scan's `SubScan.celery_ids` are ignored.
- **A stage that assessed nothing never makes a baseline.** When `vulnerability_scan` has no alive URLs, or assay writes no report, the stage stays SUCCESS but records `error_message` starting `nothing assessed`. Scoring skips such activities. If assay omits its report on a clean run, a clean rescan would not recover the score. Whether assay always writes a report on a clean run is unverified. Check it against a real clean scan before relying on recovery.
- **Never-scanned is not clean.** Only assets under an owned root that has a baseline get a score. Others return `score: None, grade: 'N/A', assessed: False`, and the UI says "Not yet vulnerability-scanned". `project_score` adds `unassessed` (the scored-but-unassessed count). `asset_count` is now the number of assessed assets, and the project score is the P10 over those.
