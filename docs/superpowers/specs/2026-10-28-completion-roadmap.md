# Completion roadmap: finish Limes as an attack-surface-management product

Status: goal set by the user on 2026-10-28 ("complete all project, enhance ui and ux following refer upguard to complete all attack surface management"), with standing permission to proceed without asking; the user reviews afterwards and asks for fixes. Every detail is my call. Reference: `docs/superpowers/specs/UPGUARD-HELP-DOCS-NOTES.md` (public help pages only).

## Streams

| # | Stream | What | Risk |
|---|---|---|---|
| L3 | Legacy stage 3 | Full-scan rescan from the Assets page (replaces the old start-scan wizard as the only way to run port scan, crawl, vigil and mantis); then retire the old results, targets, organization, subscan, scheduled-scan and interesting-lookup pages, their APIs and JS; drop their tables. Details: `legacy-audit.md` stage 3 (scratchpad copy kept in the audit report). | medium |
| L4 | Legacy stage 4 | The scan pipeline stops using `Subdomain` and `EndPoint`; drop them. | medium-high |
| L5 | Legacy stage 5 | Move scan records from `ScanHistory`/`ScanActivity`/`Command`/`Domain` to `ScanRun`/`ScanJob`/root `Asset`; data migration; rewrite tests; MCP scan ids change. | high |
| C1 | New checks | Open cloud storage (S3, Azure Blob, GCS) named after owned roots; dangling-DNS subdomain takeover; public code and secret leaks (code-hosting search for owned domains, shape-only reporting). Provisional first, like the P3 checks. | medium |
| U1 | UI/UX pass | Risk detail view per issue (what, why, how to fix, expected vs actual, first detected per asset); Home feed with "All activity" and "My tasks"; domain/asset tabs Active/Inactive; bulk label/tag edit and rescan; consistent empty/loading/error states; keyboard and screen-reader basics; mobile layout; one visual language across Overview, Issues, Assets, Lookalikes, Settings. | low-medium |
| U2 | Remediation workflow | Remediation request: pick issues, assignee, due date, message; Active/Completed/Archived tabs; live potential score impact; waiver scope (selected or all assets incl. future), expiry reminder, optional approver. | medium |
| U3 | Reporting | Executive summary page and scheduled reports (weekly to quarterly) as PDF or spreadsheet, with category breakdown. PDF must use a small dependency or the browser print stylesheet, not the removed heavy stack. | medium |
| N1 | Notifications | Alert rules (event type, severity, tag conditions) to in-app, email, webhook, Slack, Jira. | medium |
| S1 | Access | SSO (OIDC), per-project roles. | high (security) |
| D1 | Docs and release | README, docs, upgrade notes, test-instance verification, final whole-repo review. | low |

## Order

L3 and C1 in parallel (different directories), then U1, U2, L4, U3, N1, L5, S1, D1. Each stream ends with the full suite green, a reviewer pass (security-sensitive streams: C1, N1, S1, L5 get an independent opus review), and a merge to `main`.

## Anti-goals

Do not weaken the existing safety rules (owned-only active testing, rate-limit budgets that fail closed, untrusted-text escaping, provisional checks do not move the headline score). Do not add dependencies without need. Do not break the REST/MCP contracts for kept features except where stated (L5).
