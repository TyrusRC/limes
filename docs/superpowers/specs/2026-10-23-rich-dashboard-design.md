# A richer Overview: score by category, exposure, certificates, technologies and coverage

Status: continuing the UpGuard-gap roadmap the user approved on 2026-10-17 ("ok approve"), project 2 of 4; the user then asked to continue the portal on 2026-10-23 ("fix all then continue dev the portal"). Every detail is my call unless marked otherwise.
Builds on `main` after the track-owned project (P1) merges: the monitor, source names and tracking state it adds feed the coverage card.
UpGuard comparison (research notes 2026-10-17): its rating is shown as a score out of 950 and a grade, split into categories (ten since July 2025: Website, Encryption, IP Reputation, Brand, Email, DNS, Network, Data Leakage, Attack Surface, Vulnerability Management), with score history, a risk list that carries a "first detected" date, and per-asset lists.

## Intent

The Overview shows one number, a trend, counts and a table of risky assets. A person judging their attack surface wants to know **where the points are lost** (which category), **what is exposed** (ports and services), **what is about to break** (certificates), **what runs where** (technologies), **what changed** and **whether everything is actually being watched**. All of that data is already collected; the page just doesn't show it.

## Goals

- **Score by category.** Six categories, from the groups already in `limes/checks/catalogue.py` plus scanner findings:
  | Category | Source |
  |---|---|
  | Website | `web.*` checks |
  | Encryption | `tls.*` checks |
  | Email | `email.*` checks |
  | DNS | `dns.*` checks |
  | Network | `net.exposed_*` checks |
  | Vulnerabilities | scanner findings (nuclei, vigil, mantis) |
  - Each category gets a 0–950 score and an A–F grade from the same model as the headline: the penalty table and grade bands in `limes/scoring.py`, restricted to that category's issues, rolled up across assets with the same worst-weighted rule `project_score` uses. Waived issues are excluded, as in the headline. The raw (waiver-ignoring) category score is available the same way.
  - A category with nothing assessed shows "Not assessed", never a perfect score.
  - The overall score and its grade do not change. The categories explain it; they are not weighted into it.
  - `ScoreSnapshot` gains a `categories` JSON field (`{"web": 950, …}`), written by `snapshot_scores`, so each category can show its change against 30 days ago. One migration. Old snapshots have no categories and show no trend.
- **Category cards on the Overview:** score, grade, number of open issues in the category, change since 30 days ago, and a link to the Issues page filtered to that category. The Issues API and page gain a `category` filter.
- **Exposure card.** Services seen on owned IPs: a table of port, service name, number of hosts, with risky ports (`RISKY_PORTS`) marked and linked to the matching issue filter. Data: the InternetDB results already stored on IP assets.
- **Certificates card.** Certificates expiring in the next 30 days (and any already expired): host, expiry date, days left, severity. Data: the `not_after` evidence the TLS checks store.
- **Technologies card.** The ten most common detected technologies with counts and a link to the Assets page filtered by technology. Data: `Asset.technologies`.
- **Remediation card.** Issues fixed in the last 7 and 30 days, issues opened in the same periods, and the oldest open critical or high issues with their age ("first detected"). Data: `TrackedIssue` (`first_seen`, `fixed_at`, `reopened`).
- **Discovery card.** Owned assets by how they were found: manual, certificate transparency, scan, passive intel, ASN, IP range. Data: `Asset.sources`.
- **Coverage card.** How much of the owned inventory is actually watched: assets checked within their cadence, overdue, never checked, stopped (cadence off), with the oldest unchecked asset. Data: the monitor state and last-checked fields the track-owned project adds.
- **Top risks.** The ten open issues costing the most points, each with asset, severity, points and "first detected" (date and age; reset when a fixed issue comes back, as `TrackedIssue.reopened` already records), linking to the Issues page.
- **"What changed" panel** beside the score history, with a 30-day / 90-day toggle: new assets, removed (missing or retired) assets, issues introduced, issues resolved, and the score change. Data: `Asset.first_seen` and lifecycle state, `TrackedIssue`, `ChangeEvent`. This is UpGuard's "View Changes" panel; it explains *why* the line moved.
- **No new data collection** and no change to the score. Every widget reads data the system already stores.

## Non-goals

- New categories whose data doesn't exist yet: IP Reputation, Brand (typosquatting) and Data Leakage. They arrive with project 3. Until then the page says nothing about them (no empty placeholders that look like a perfect score).
- Peer benchmarking and vendor comparison (UpGuard's data is proprietary).
- Weighting categories into the headline score, or changing the penalty table, ceilings or grade bands.
- Per-category history charts. Only the 30-day change is shown.
- A configurable dashboard (drag and drop, hide and show). Fixed layout.

## Anti-goals

- **A category score that disagrees with the headline.** The sum of what the categories explain must reconcile with the headline's inputs: a test builds a project with issues in several categories and checks each category's score against `limes/scoring.py` computed by hand, and that the issue counts across categories add up to the open issues the Issues page lists.
- **A perfect-looking score for something never checked.** Unassessed means "Not assessed".
- **Untrusted text breaking the page.** Hostnames, certificate subjects, technology names and issue titles come from scanned hosts: every one is escaped, and the existing hostile-name check (an asset named like markup) must pass on every new card.
- **A slow page.** The Overview is cached for 60 seconds today (`dashboard/stats.py`, `invalidate()` exists); the new queries stay bounded (no query per asset), and the page's total query count is asserted by a test.
- **Cross-project data.** Every new query is scoped to the current project.

## Design (my calls)

- **`limes/scoring.py`** gains `category_scores(project, now=None) -> dict`, reusing `_penalties` and the roll-up so there is no second scoring model. The category of an issue key comes from one small function `category_of(key)`: the check group for check ids, `'vulnerabilities'` for scanner findings.
- **`dashboard/stats.py`** gains the card builders, one function each, all returning plain dicts (the page template only formats them), and the existing cache wraps the whole result.
- **UI** follows the restyle's tokens and card layout (`limes.css`, `ov-*` classes); category cards use the existing grade colour classes. The page order: score, trend, category cards, attack surface counts, severity tiles, then Exposure, Certificates, Technologies, Remediation, Discovery, Coverage, Top risks, Recent changes. On 390px they stack.
- **Issues page filter:** `category` is added to `/api/issues/` and a select on the page. Anything outside the six known values is ignored.

## Backlog from UpGuard's public help documentation (not part of this project)

Research notes: `docs/superpowers/specs/UPGUARD-HELP-DOCS-NOTES.md` (cited, public pages only; screenshots in the docs were unreadable, so layout detail is thin). Ranked by value and feasibility for Limes, after what this project covers:
1. An "informational" tier that is shown but never scored, and "provisional" new checks that start with no score impact.
2. Risk detail view: what was detected, why it matters, recommended action, expected versus actual value, first detected per asset.
3. Waiver scope (all assets including future ones, or selected), expiry reminder, optional approver, internal-only choice.
4. Remediation-request flow (pick issues, recipient, due date, message; Active/Completed/Archived tabs; live potential score impact).
5. Domain list tabs Active / Inactive (active = open port or MX), bulk label edit, rescan button (the activity rule is already used by the monitor).
6. Portfolios: asset groups with inheritance from the parent domain and a current-portfolio switcher that filters every page and export.
7. Notification rules (event type, severity, time frame, label/portfolio conditions) to in-app, email, webhook, Slack, Jira, plus a Home feed with "All activity" and "My tasks".
8. Executive summary and scheduled reports (weekly to annual, PDF or spreadsheet) with category breakdown.
9. Vulnerabilities page with EPSS, a CISA known-exploited marker (both free datasets), a verified filter and an Ignored tab.
10. New checks UpGuard markets that Limes lacks: exposed AI/LLM endpoints, exposed Supabase-style databases.

## Left to the builder

- Exact column sets, card order within a row, wording of empty states, and chart marks for the 30-day change.
