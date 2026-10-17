# Risk checks: UpGuard-style configuration checks

Status: written 2026-10-17; awaiting the user's review.
Builds on `main` at `ca7a73a`: the A4 score (`limes/scoring.py`), A5b continuous scanning, and the A-dash dashboard.

## Intent

The user wants Limes to be a self-hosted alternative to UpGuard Breach Risk. A gap analysis on 2026-10-17 compared UpGuard's published features with Limes. UpGuard's rating is built mainly from hundreds of passive configuration checks: website headers, email, DNS, TLS and exposed services. Limes scores only vulnerability findings, so its score is not comparable. The user chose risk checks as the first gap to close.

Success means three things:
- Every owned host and root gets a set of pass/fail configuration checks with evidence.
- Failed checks feed the published score.
- A person can see exactly which check cost points and how to fix it.

## Goals

- A catalogue of about 25 checks across five groups: website, TLS, email, DNS and network.
- Checks run automatically in every scan, including the `asm` runs that continuous monitoring starts, with no manual trigger.
- One current result per (asset, check): first seen, last checked, status and evidence. A check that starts passing is fixed immediately.
- The score becomes `limes-score-v2`. Failed checks are penalties with published weights, alongside vulnerability findings.
- The UI shows the results. Each asset's detail view gets a Risks section, failed checks appear among the score card's top penalties, and every check has a one-line "how to fix".

## Non-goals (for this slice)

- DKIM. It needs selector guessing and is noisy.
- The full TLS cipher-suite matrix.
- KEV/EPSS weighting. That is its own follow-up.
- Waivers and remediation workflow (roadmap #1). The data model must not block them later.
- Alerts (roadmap #3).
- Typosquatting, leaked credentials and news feeds.

## Anti-goals (a failure even if it works)

- **Anything that looks like an attack.** Checks are at most one HTTPS GET of `/`, one TLS handshake, and the same for plain HTTP to test the redirect. Everything else is DNS lookups, or ports Limes already knows.
  - No path brute-forcing, no fuzzing.
  - No TLS downgrade beyond one handshake attempt per legacy protocol version.
- **Contacting anything outside scope.** Every network contact goes through the existing scope guard at contact level (`scope.may_contact`), the same level as screenshots. Only owned assets are checked.
- **Noisy, unexplainable results.** Every failed check carries its evidence: the header value seen, the certificate's expiry date, the DMARC record text, the open port and where it came from.

## Constraints

- Self-hosted, with no paid feeds. It may use only the Python stdlib (`ssl`, `socket`), `requests` (already a dependency) and `dnspython` (added in A5a).
- It must be fast enough to run in every `asm` run: bounded per host, with short timeouts, and at most `MAX_HOSTS` hosts per run. The rest are checked on the next run.
- It reuses the scan identity: the project's User-Agent and headers (`limes.identity`) for HTTP requests.
- It follows existing repo conventions: tabs in `stages.py`, 4 spaces elsewhere, an argv list never a shell, TDD, and no network in tests.

## Decided

- **The check catalogue**, as proposed and accepted as a starting point:

  | Group | Applies to | Checks |
  |---|---|---|
  | Website | owned hostnames and roots that answer HTTP(S) | HTTPS not available; HTTP does not redirect to HTTPS; no HSTS; no CSP; no X-Frame-Options or `frame-ancestors`; no X-Content-Type-Options; cookies missing Secure / HttpOnly / SameSite; Server or X-Powered-By reveals a version |
  | TLS | same, on 443 | certificate expired; certificate expiring within 14 days; hostname mismatch; self-signed or untrusted chain; TLS 1.0 or 1.1 accepted |
  | Email | owned root domains | SPF missing; SPF `+all` or `?all`; DMARC missing; DMARC `p=none`; MX present without SPF or DMARC |
  | DNS | owned root domains | DNSSEC not enabled (no DS at the parent); no CAA record |
  | Network | owned IPs | a risky service exposed: FTP 21, Telnet 23, SMB 445, RDP 3389, MSSQL 1433, Oracle 1521, MySQL 3306, Postgres 5432, Redis 6379, Elasticsearch 9200, Memcached 11211, MongoDB 27017, Docker API 2375, VNC 5900. The ports come from InternetDB enrichment and naabu results Limes already stores. |

- **It runs as a scan step in every mode**, including `asm`, so continuous monitoring covers it.
- **One current result per (asset, check)**, not one per scan.
- **The score includes failed checks**, as `limes-score-v2` with published weights.

## Calls I made (the user can override)

- **Severity per check**, using the same penalty table as findings (critical 200, high 80, medium 25, low 5):
  - **high:** expired certificate; self-signed or untrusted certificate; hostname mismatch; HTTPS not available on a host that serves HTTP; exposed database, Redis, Elasticsearch, Memcached, MongoDB, Docker API, SMB, RDP, Telnet or VNC;
  - **medium:** TLS 1.0/1.1 accepted; HTTP not redirecting to HTTPS; no HSTS; DMARC missing; SPF missing, `+all` or `?all`; certificate expiring within 14 days; FTP exposed;
  - **low:** every other check (CSP, X-Frame-Options, X-Content-Type-Options, cookie flags, version leaks, DMARC `p=none`, DNSSEC, CAA, MX without SPF/DMARC).
- **Assessment:** an asset counts as assessed when it has risk-check results *or* a vulnerability baseline. Projects that only run `asm` scans therefore get a score from configuration checks, as UpGuard does.
  - Penalties from checks and findings add together, and per-category de-duplication still applies (category = check id).
  - The ceilings (any critical → C, any high → B) apply to both sources.
- **Freshness:** a failed check counts only if it was checked within the last 30 days. Older results are shown as stale and not scored, so a host that disappeared stops costing points.
- **Where results live:** a new model, `RiskCheck` (asset, check id, status pass / fail / error, severity, evidence JSON, first_seen, last_checked).
  - An `error` result, such as a timeout, is never a fail and never scores.
  - The model is kept separate from `Vulnerability`, which is one row per scan and would double-count.
- **Code layout:**
  - `limes/checks/` contains one small module per group, each with pure functions that turn collected observations into results;
  - a separate collector does the network I/O, with injectable functions so tests never touch the network;
  - a `risk_checks` stage task runs after `passive_intel`.
- **Limits:** a 5s timeout per network operation and `MAX_HOSTS = 200` per run, oldest-checked first, with a `NOTE:` naming the ceiling.
- **Coverage:** the score card shows "N% of owned assets checked in 30 days" next to the existing vulnerability-coverage line.

### Calls made after the builder check (2026-10-17)

- **Owned IPs are scored assets.** `scoring.scored_assets` widens to include `kind='ip'` with an owned tier, the way UpGuard rates domains and IPs separately. An IP's exposed-service failures count on the IP's own row only and are never copied to the hostnames that resolve to it, so shared IPs never double-count. IPs enter the P10 and the asset counts.
- **Where ports come from.** The network checks take the union of:
  - InternetDB ports in `Asset.enrichment['internetdb']`, counted only if `fetched_at` is within 30 days;
  - naabu ports on the `IpAddress` row whose `address` equals the IP asset's value.

  The evidence records which source saw the port, with its date. A port seen by either source fails the check: naabu not seeing an InternetDB port is not proof it is closed. When neither source has fresh data for an IP, its network checks are `error` (not assessed), never `pass`.
- **Placement in the workflow.**
  - `asm`: `subdomain_discovery → passive_intel → risk_checks → screenshot`.
  - `full` / `scanner`: `risk_checks` runs directly after `port_scan`, so naabu ports are present.

  A failing `risk_checks` stage behaves like any other stage: it is marked failed, the rest of the scan continues, and the step's other results are kept.
- **Which hosts get web and TLS checks.** The probe is the check. It tries HTTPS on 443, then HTTP on 80. A host that answers neither gets `not_applicable` for every website and TLS check. That is neither pass nor fail, and it is not scored. "HTTPS not available" fails only when HTTP answers and HTTPS does not.
- **Root-level checks are not inherited.** Email and DNS results belong to the root asset only. A missing DMARC record costs points once, on the root, never on each subdomain.
- **Assessment and history.**
  - An asset is assessed when it has at least one non-`error`, non-`not_applicable` result within 30 days, or a vulnerability baseline.
  - `ScoreSnapshot` keeps its `version` field, so v1 history stays as it is. The dashboard trend marks the point where the version changes, so the jump to v2 doesn't read as a sudden drop.
- **Cap and freshness.** `MAX_HOSTS = 200` is per run, which means per project root. Hosts are picked oldest-checked first. If results age past 30 days because the estate is larger than the cap, they stop scoring. The "N% of owned assets checked in 30 days" coverage line makes that visible, and the `NOTE:` on the cap names it as the ceiling.

## Left to the builder

- Exact check ids and help text, written as one plain sentence each.
- How the collector bounds concurrency, as long as the per-host limit and timeouts hold.
- The migration, the serializer and template details, and whether results are added to the asset retrieve API as `risk_checks` or folded into `risk`.
- Test fixtures: fake HTTP responses, TLS observations and DNS answers.

## Open risks

- **CDN and WAF hosts** may answer differently to Limes than to a browser. Only what was observed is recorded, so "no HSTS" behind a CDN is a real observation of what the CDN served.
- **Legacy TLS probing** needs an `ssl` context that allows TLS 1.0/1.1. Some OpenSSL builds can't do that at all. When the local OpenSSL refuses, the check must report `error`, never `pass`.
- **Hosts behind authentication or redirect loops** give poor header evidence. The check follows at most 3 redirects within the same host and evaluates the last response.
