# ASM platform roadmap (Limes: self-hosted UpGuard replacement)

Status: agreed in brainstorming, 2026-10-07. Each sub-project gets its own spec → plan → implementation cycle. This document records the decisions that span sub-projects so later specs do not re-litigate them.

Research basis: `reports/UpGuard replacement ASM design.md` (local, git-excluded) and the UpGuard UI/feature gap review held in the brainstorming session.

## Goal

An enterprise, self-hosted external attack surface management platform for one organization (with subsidiaries), used by a team of under 20, that replaces UpGuard Breach Risk. It must be fast, stay in sync with its scan engine, find more assets than stock open-source recon, scan continuously without manual triggers, and stay quiet: few, trustworthy, prioritized findings.

## Constraints and principles

- Self-hosted with Docker on hardware the organization controls. Single tenant. Sizes itself to the host it runs on.
- External assets only. Internal network scanning is out of scope.
- Active testing runs only against assets confirmed as owned. Everything else gets passive checks only (see Scope tiers).
- The same image runs every service, so scan capacity can grow by adding worker hosts.
- Secrets never appear in the repo, logs, command history, or the UI.
- Scoring is published and explainable; no black box.

## Sub-projects and order

| # | Sub-project | Depends on |
|---|---|---|
| 0 | Performance, stability, default pipeline, scan identity | — |
| 1 | Team collaboration: SSO, 3 roles, audit log, assignment, comments, remediation requests, waivers, false-positive disposition | 0 |
| 2 | Asset inventory + continuous discovery + attack-surface graph + intelligence providers + cloud connectors | 0 |
| 3 | Change alerts, digests, Risk Automations (event → ticket/webhook) | 2 |
| 4 | Risk findings + published score + DNS/email/reputation/geo-sanctions checks + Detected Products | 2 |
| 5 | Typosquatting (dnstwist, CT lookalikes, abuse-report generation) | 2 |
| 6 | Vendor risk (passive only) + fourth parties | 2, 4 |
| 7 | Executive and scheduled reports, subsidiaries reporting | 4 |
| — | assay changes (separate spec in the assay repo): per-host `--rps` limiter, `RequestIdentity` applied to every traffic path | needed by 0 for full header coverage |

Optional paid connectors, decided per budget later: identity-breach / infostealer data (e.g. HIBP domain search), paste/forum/marketplace monitoring, deep passive DNS, reverse WHOIS. Free: ransomware.live leak-site mentions, Shodan InternetDB, RIPEstat, crt.sh.

Out of scope: industry-average benchmarking (needs a global dataset), vendor questionnaires / Trust Center, User Risk (browser extension, SaaS usage).

## Cross-cutting decisions

### Tooling (default pipeline, no per-tool plug-and-play)

amass (v5, read from its asset DB) + subfinder → dnsx → naabu → nmap `-sV` on open ports → httpx (incl. screenshots) → katana + gau → assay (DAST; runs nuclei internally) → mantis (`mantis.audit()` SAST, `secrets`/`web` packs) on JS, source maps and exposed `.git` collected by the crawl. Coverage additions in sub-project 2: puredns/shuffledns with validated resolvers, alterx, tlsx on owned ranges, waymore, katana headless only on SPAs, OpenAPI import into assay. Scan engines become profiles (`quick`, `normal`, `thorough`, `passive`) that tune depth and limits, not which tools run.

Removed: sublist3r, oneforall, ctfr, tlsx-as-discovery, gospider, hakrawler, waybackurls, EyeWitness (+ Firefox/geckodriver), standalone nuclei task, dalfox, crlfuzz, wafw00f, GooFuzz. OSINT (theHarvester, h8mail) and ffuf are deferred.

assay is never invoked with `--h2-reset`, `--h2-continuation`, `--h2-madeyoureset`, `--redos`, `--mass-assign` or `--proto-pollution-server` on scheduled scans. assay `serve` is not used (unauthenticated, in-memory); assay runs as a subprocess with an argument list.

### Scope tiers

| Tier | Enumerate under it | Scans |
|---|---|---|
| Owned root | yes | full active |
| Owned host / IP / CIDR | — | full active |
| Co-brand host (exact FQDN on a third-party domain) | never; its registrable domain never enters the root set | passive by default; active only after a per-asset "authorized" opt-in recording the provider's testing permission. No port scan of its shared IPs; httpx 80/443 by hostname; katana `-fs fqdn`; redirects recorded, not followed |
| Candidate | no | passive enrichment only, review queue |
| Rejected | no | none; remembered so it is never re-suggested |

Shared CDN / SaaS / cloud IPs are Dependency nodes and are never scanned by IP. The scope check runs at every active stage, not only at intake. Manual adds are confirmed by the adding user (audited); private and reserved IP ranges are rejected.

### Attribution and graph

Postgres node/edge tables (domain, host, IP, CIDR, ASN, cert, org/registrant, NS, MX, favicon hash, tech, SaaS provider, cloud account; typed edges with source, confidence, first/last seen). Ownership is computed from evidence with confidence decaying per hop (max depth 2). Above threshold auto-confirms; middle goes to a Confirm/Reject review queue; below is dropped. Every asset shows its "why is this mine?" path. Keyword matching uses whole-label brand matches, never substrings.

### Inventory and cadence

Inventory-first: assets exist independently of scans; scans are per-asset, per-stage jobs. A one-minute dispatcher picks due work from Postgres. Cadence tiers: crown jewel (probe hourly, DAST daily), standard (probe daily, DAST weekly), inactive (monthly). New assets (manual, CT via certstream-server-go ≥ v1.9, cloud DNS events, discovery) enter the pipeline immediately; a fingerprint change (response hash, tech, cert) re-crawls and re-tests only that asset. Asset lifecycle: active → missing (3 consecutive successful-run misses) → stale → retired. "Rescan now" exists on assets, issues and remediation requests.

### Noise control

Confidence tiers: Verified (assay proof or behavioural nuclei match) alerts and scores; Likely scores and goes to digest; Unverified (banner CVEs, low confidence) is visible only. One canonical finding per (asset, type, location, parameter) with first/last seen and status Open / Fixed (only after a verification rescan) / Waived / False positive / Regressed. Issues group the same finding across assets. Priority = severity × KEV/EPSS × exposure × crown-jewel tag. Immediate alerts only for change events (new verified critical/high, regression, takeover, cert expiring within 14 days, new owned asset exposing a sensitive service); everything else is a daily digest. Detector precision is tracked from false-positive marks; detectors over threshold are demoted to Likely. Optional local-LLM triage ranks but never closes critical/high.

### Score

UpGuard-compatible 950-point model with published weights in versioned configuration (proposed defaults in the research report: critical 200 / high 80 / medium 25 / low 5; per-category cap; critical ceiling C, high ceiling B; weakest-link roll-up with a P10 floor). Raw and waiver-adjusted scores, daily snapshots with model version, top penalties and coverage. Required invariant tests: merger invariance, monotonicity, immediate recovery on verified fix, waiver expiry.

### Scan identity

Per project with per-asset override: User-Agent plus headers (`Domain.request_headers` is reused). Applied to httpx (explicit UA, no `-random-agent`), katana, assay; not applicable to DNS/TCP-only tools. Secret header values are stored encrypted (key from environment), passed to tools via 0600 temp files deleted after use, and redacted in recorded commands.

### UI

UpGuard's proven pattern: product rail + grouped section nav (Overview, Workflows, Inventory, Threat Intel, Tasks); every list = title + one-line explanation + Apply filters + Export + table; a row opens a side drawer with evidence, actions (Manage risk, Rescan, Request remediation, Export PDF). Domains have table and tree views. Score card with 1/3/12-month trend and drag-to-inspect changes, showing exact point deltas. Default stack: Django templates + htmx + Alpine.js + cytoscape.js for the graph; confirm or switch to a React SPA in the first UI spec.

### Enterprise non-functional requirements

- SSO (SAML/OIDC), roles Admin / Standard / Read-only, full audit log.
- Backups of Postgres and the artifact volume with a documented restore; data retention settings for raw tool output.
- Health endpoints and per-service healthchecks; metrics (queue depth, task latency, stuck jobs, provider quota).
- Horizontal scan capacity via additional `worker-scan` hosts (requires TLS + auth on Redis/Postgres; designed in sub-project 2 or later).
- No default credentials in the repo; installer generates secrets.
