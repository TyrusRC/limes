# ASM module — Slice A-dash: Inventory-first dashboard

Status: design approved in brainstorming 2026-10-15; awaits user review of this file before planning.
Parent: Limes ASM platform. Builds on A4 (risk score), `main` at `c3e86a6`.
Spec basis: `docs/superpowers/specs/2026-10-07-asm-platform-roadmap-design.md` § "UI" (an overview built around inventory and risk; each list says what it shows and links to the filtered inventory), and the A2 spec, which deferred the dashboard to this slice.

Platform: Django 3.2 templates + jQuery + ApexCharts (already loaded on the dashboard), PostgreSQL.

## Module context

ASM slices: A0–A3c ✓ · A4 ✓ · A5a ✓ · A5b ✓ · **A-dash this slice**.

## Problem (found in code, 2026-10-15)

`dashboard/stats.py::_compute` reads the legacy per-scan tables: `Subdomain`, `EndPoint`, and `Vulnerability` filtered by `scan_history`. Each rescan writes new rows, so its totals and charts double-count. It ignores scope tiers, the asset lifecycle, the A4 score, the attribution review queue and continuous scanning. Only `dashboard/views.py::index` and `dashboard/templates/dashboard/index.html` consume it, plus `tests/core/test_dashboard_stats.py`.

## Goal

The project dashboard answers five questions at a glance:
- How risky are we, and is it getting better?
- What do we own?
- What needs a human decision?
- What changed this week?
- Is monitoring running?

## Scope

**In:**
- replace `_compute` with `asm_stats(project)`, keeping the cache key, the 60s TTL and `invalidate`;
- rewrite `index.html`;
- replace `test_dashboard_stats.py`.

**Out:**
- the global (non-project) views;
- notifications;
- the Assets page;
- any new model or API.

The legacy charts are removed:
- the subdomain, endpoint and vulnerability totals and weekly sparklines;
- the world map;
- the "most common IP/port/technology/CVE/CWE/tag" panels;
- the vulnerability feed.

The legacy tables and their own pages stay untouched.

## Design

### 1. Data: `dashboard/stats.py`

`project_stats(project)` keeps its signature, cache key and TTL, and now returns `asm_stats(project)`, a dict:

**`risk`:** `limes.scoring.project_score(project)` (score, grade, coverage, asset_count, unassessed, top_penalties, version), plus `trend`, a list of `{date: 'YYYY-MM-DD', score}` from the last 30 `ScoreSnapshot` rows, oldest first.

**`inventory`:**
- counts of `owned_root`, `owned_host`, `ip` (owned tiers) and `dependency` assets;
- `states`, a count per state (`active`, `missing`, `stale`, `retired`) over owned assets.

**`review`:**
- `candidates`: candidates with `confidence` null or ≥ `attribution.REVIEW`, the same rule as the Assets list default;
- `would_auto_confirm`: candidates whose `confidence_detail` contains `would_auto_confirm: true`.

**`changes`:**
- `new_owned`: owned assets with `first_seen` in the last 7 days, newest first, at most 10, each as `value`, `kind`, `first_seen`;
- `missing`: owned assets currently `missing`, most recently seen first, at most 10;
- `auto_confirmed`: assets whose `sources` include `source == 'attribution'` and whose `decision_reason` starts with `auto-confirmed`, filtered to the last 7 days by the matching source entry's `seen_at`, at most 10.

**`findings`:** a count per severity (critical, high, medium, low) of open findings in the score's baseline scans (`scoring.baselines`), on assessed assets only. This matches what the score counts, except that categories are not de-duplicated: these are finding counts, not penalties.

**`monitoring`:**
- `enabled`: `settings.CONTINUOUS_SCANS`;
- `running`: scans of this project in INITIATED or RUNNING state;
- `next_due`: up to 5 of `continuous.due_roots(now)` that belong to this project, as `value` and `cadence_tier`;
- `last_auto`: `start_scan_date` of the latest scan of this project with `initiated_by` null, or null if there is none.

**`activity`:** the latest 15 `ScanActivity` rows of this project's scans. Today's feed shows 50; 15 keeps the page short.

### 2. Template: `dashboard/templates/dashboard/index.html`

Bootstrap cards in the existing theme, top to bottom:
1. **Risk.**
   - A large score and grade badge, or "Not yet vulnerability-scanned" when the score is null and assets are unassessed, or "No owned assets yet".
   - The coverage line, and "N assets not yet scanned".
   - An ApexCharts line chart of `trend`, which is hidden when it has fewer than 2 points.
   - A top-penalties table.
   - A link to the Assets page.
2. **Inventory.**
   - Four count tiles: owned roots, owned hosts, IPs, dependencies.
   - A lifecycle row.
   - A **Review queue** tile showing candidates and "N would auto-confirm". It links to the Assets page with `?scope_tier=candidate`.
3. **This week.** Three short lists: new owned assets, missing, auto-confirmed. Each has an empty state.
4. **Findings on owned assets.** Severity badges.
5. **Monitoring.**
   - "Continuous scanning on/off";
   - running count;
   - the next-due table (root, cadence);
   - "Last automatic scan: <date | never>".
6. **Recent scan activity.**

Every value goes through Django auto-escaping. The trend data is passed with `json_script`, never interpolated into JavaScript. The page loads no world-map or legacy chart scripts.

### 3. Assets page filter link

The Assets page already reads `scope_tier` from its filter select. The review-queue link sets that select from `?scope_tier=` on load: a small read of `location.search` in `assets.html`, applied only if the value is one of the select's options.

## Data flow

1. A request to `/<slug>/dashboard/` calls `project_stats`, which returns the cached result or computes `asm_stats`.
2. The template renders.
3. Asset decisions and scan completion already call `invalidate(project_id)`, so the page refreshes within 60s otherwise.

## Testing

`tests/core/test_dashboard_stats.py` is replaced:
- **Project isolation:** another project's assets, findings, snapshots, scans and activity never appear in any section.
- **Inventory:** tier counts, and state counts over owned assets only.
- **Review queue:** a candidate below `REVIEW` is excluded, a null-confidence candidate is included, and `would_auto_confirm` is counted.
- **Changes:** an owned asset first seen 6 days ago is listed and one seen 8 days ago is not. Missing ordering. An auto-confirmed asset from 8 days ago is excluded.
- **Findings:** they equal the baseline scans' open findings on assessed assets, and an older scan's findings are excluded.
- **Monitoring:** due roots are limited to the project, and `last_auto` ignores scans that have a user.
- **Trend:** oldest first, at most 30 entries.
- **Cache:** a second call within the TTL does not recompute, and `invalidate` forces a recompute.

**UI:** a real Chromium run of the dashboard:
- each section renders with seeded data;
- an XSS payload in an asset value and a finding name stays text;
- an empty project shows the empty states;
- there are no console errors;
- the template compile check passes.

## Review focus

1. **Cross-project leakage** in any section, especially `next_due`, because `due_roots` is global.
2. **The findings count must not disagree with the score's baselines.** For example, it must not count findings from a scan that is not a baseline.
3. **The `json_script` trend** must not be breakable by its data.
4. **A project with no scans, assets or snapshots** must render without errors.
5. **Removing the legacy blocks** must not leave the template referencing missing context keys.

## Risks

- **Users lose the legacy charts.** They double-counted and ignored scope. The legacy scan pages still show per-scan detail.
- **Cost of `project_score` and `due_roots`.** Both run several queries per root. The 60s cache bounds the cost. The upgrade path is snapshot-backed numbers for large estates.
