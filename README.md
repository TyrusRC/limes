# Limes

Self-hosted external attack surface management for one organization. Limes keeps an inventory of
the domains, hosts, IPs, ranges and ASNs you own, discovers new ones continuously, scans them with a
fixed, quiet pipeline, turns what it finds into a risk score, and tells you when something changes.

Active testing only ever runs against assets confirmed as owned; everything else gets passive
checks. See [the roadmap](docs/superpowers/specs/2026-10-07-asm-platform-roadmap-design.md).

## What it does

| Area | What you get |
|---|---|
| **Inventory** | Every owned root domain, hostname, IP, CIDR range, ASN and API, with how it was found, when it was first and last seen, and its state (active, missing, stale, retired). Candidates found by passive sources wait in a review queue until you confirm or reject them. |
| **Tags** | Label assets with project-scoped tags (for example `payments` or `prod`) from the Assets page, in bulk through the API (`POST /api/action/asset/tags/`) or over MCP (`tag_assets`). Filter assets and issues by tag; the Overview shows a score per tag (the same model as the headline score, which it never changes). At most 20 tags per asset and 200 per project. |
| **Discovery** | Certificate transparency, Shodan InternetDB, RIPEstat, DNS resolution and ownership scoring find new assets; auto-confirm needs a registry-verified delegation. Anything the tools miss you add by hand (domain, IP, range such as `203.0.113.0-203.0.113.255` or `203.0.113.0/24`, or `AS64500`) and it is tracked from then on. |
| **Continuous tracking** | Owned roots are rediscovered on a cadence (every 24 hours, 7 days or 30 days, or off). Hosts and IPs outside a scanned root are checked by a light monitor: daily when they have an open port, a live web answer or a mail record, monthly otherwise. |
| **Risk score** | A 0–950 score with an A–F grade (`limes-score-v3`): any critical finding caps the grade at C, any high at B. Waived issues are scored out of the headline and the raw score is shown beside it. |
| **Risk checks** | TLS certificates and protocols, HTTP security headers and cookies, SPF/DMARC, DNSSEC/CAA and exposed risky services, run against owned assets. |
| **API discovery** | After the web probe, owned hosts that answered are asked (GET only, at most 12 well-known paths) for an OpenAPI/Swagger document or a GraphQL endpoint. Each API found becomes an `api` asset under its host, with title, version, endpoint count and auth schemes. Three provisional checks (`api.exposed_docs`, `api.no_auth_declared`, `api.unauthenticated_access`, which fetches at most 20 documented GET paths once each) are shown and tracked, never scored. A server URL on another host is recorded as text only. |
| **Findings** | vigil (DAST, runs nuclei) and mantis (SAST on the JavaScript, source maps and exposed `.git` the crawl collects). |
| **Change alerts** | New and returning issues, dropped scores, new assets and expired waivers go to in-app notifications, Slack, Discord, Telegram or Lark, and a signed webhook. High-signal changes alert immediately (at most 10 per project per hour); the rest arrive in one daily digest. |
| **Subsidiaries and portfolios** | A project can hold subsidiaries: named entities whose assets are grouped under them (a root's hosts follow the root; `GET/POST/DELETE /api/subsidiaries/`, `POST /api/action/asset/subsidiary/`, MCP `list_subsidiaries`). Each is scored like the headline over its own assets only; the headline never changes. The Overview lists them in a roll-up table and the Issues list toggles "Organization and subsidiaries". A portfolio is a saved named filter (tags and/or one subsidiary, plus hand-picked assets; `/api/portfolios/`, MCP `list_portfolios`). The header's "Current portfolio" menu filters the Overview findings, Issues, Assets and CSV exports; the pick lives in the session and is checked against the project on every request. It is a view, not an access rule. Writes need the modify-targets permission. |
| **Alert rules** | Per-project rules pick events (kind, minimum severity, asset tags, score drop within N days) and send them, on top of the default alerts, to in-app, email, a signed webhook, Slack or Jira Cloud (one Jira issue per new issue, never duplicated). Integration secrets are encrypted at rest and never shown again; every URL must be public https. See [docs/alerting.md](docs/alerting.md). |
| **Waivers and notes** | Accept a risk until a date (default 90 days, at most 365) or mark a false positive, with a reason and an audit trail, for one asset or for every asset with that issue including ones found later. Name an approver and the waiver does not count until they approve it. A reminder lands in-app (default 7 days before it ends), and the Waivers page lists current and past waivers. Discuss issues in notes; see the score if chosen issues were fixed. |
| **Remediation requests** | Pick issues in a three-step wizard (select, recipients and due date, review with the live potential score impact), assign a team member or up to 10 external email addresses, and track the request in Active/Completed/Archived tabs with a message thread and timeline. A request completes itself when all its issues are fixed; overdue ones show in My tasks. Read over MCP with `list_remediation_requests` and `get_remediation_request`. See [`docs/remediation.md`](docs/remediation.md). |
| **IP reputation** | Owned IPs, ranges and ASNs are checked against Spamhaus DROP and ASN-DROP and the abuse.ch Feodo list (opt-in: blocklist.de, CINS; optional Spamhaus DQS). Provisional until the feeds prove themselves: shown, alerted, never scored. |
| **Exploitability** | Findings and InternetDB banner CVEs carry CISA KEV and EPSS markers; Top risks use them only to break ties, and the Issues page filters on "Known exploited". |
| **Exposure and leaks** | Exposed AI services (Ollama, OpenAI-compatible APIs, Triton, Gradio, Jupyter, Ray) on owned IPs, Supabase secret keys in client JavaScript, and, with a key, Have I Been Pwned domain breaches (counts only). |
| **Cloud, takeover and code leaks** | Three more provisional checks (shown and tracked, never scored). `cloud.open_storage` tests up to 24 bucket names per owned root (the label with suffixes like `-backup` or `-assets`) on S3, Azure Blob and GCS with one GET each, and flags only a response that proves anonymous listing; it keeps provider, name and an object count, never object names. `dns.dangling_takeover` flags an owned hostname whose CNAME points at a takeover-prone provider (GitHub Pages, Heroku, S3, Azure, Fastly, Shopify, Netlify, Surge and a few more) when the target no longer resolves or the provider answers with its "unclaimed" page; it nominates hosts from stored DNS data, confirms the CNAME with a live query, looks at up to 200 hosts and 15 minutes per run, oldest first, and keeps a fingerprint id, not the page. `leak.public_code` (opt-in, needs `LIMES_CODE_SEARCH_TOKEN`) searches GitHub code for each owned root and flags a repository only when the domain (at a hostname boundary) and a credential shape (Supabase keys, AWS access key ids, GitHub, Slack, Stripe and Google keys, private-key headers) sit on the same line, and reports an error rather than a pass when there are more results than the three pages it reads; it keeps repository, path and a masked shape. Only the providers' own hostnames are fetched; daily budgets (60 code-search pages, 2000 GETs for each of the other two) fail closed and a project gets at most a quarter of each; a failed check is retried after 6 hours. |
| **Mail policy and name servers** | Five more provisional checks (shown and tracked, never scored). For an owned root with MX hosts: `email.mta_sts_missing` (no `_mta-sts` TXT), `email.mta_sts_testing` (fetches `https://mta-sts.<domain>/.well-known/mta-sts.txt` once, through the pinned `safe_fetch` getter, no redirect, 64 KB, 2000 GETs a day shared and a quarter per project, fails closed; flags mode testing or none, a missing or short `max_age`, a wrong version, or MX hosts the `mx` lines do not cover), `email.tls_rpt_missing` (no `_smtp._tls` TXT with `rua`) and `email.bimi_invalid` (a BIMI record exists but DMARC is not quarantine/reject, or the logo is not HTTPS). `dns.dangling_ns` flags a name server in the delegation whose name is NXDOMAIN (registrable by anyone); a failed lookup is an error, never a pass. Evidence keeps modes, numbers and problem codes, never policy text. Not built: a DKIM selector check (selectors are arbitrary, so "absent" cannot be told from "uses another selector") and lame-delegation (needs direct queries to third-party name servers, outside the pinned/vetted model). |
| **Lookalikes** | Typo, homoglyph, TLD-swap and keyword variants of each owned root are checked through DNS, RDAP and certificate transparency. Registered ones land in a review queue (watch, ignore, this is ours, abuse-report text to copy); the Overview has a Brand card. Limes never sends the report. |
| **Reports** | A printable executive summary (score and grade with trend, score by category, top risks, remediation, what changed, per-tag scores, exposure, certificates, brand), filterable by tag and 30/90/365 days; the browser's Save as PDF makes the file. CSV exports of issues and assets. Recurring weekly, monthly or quarterly reports are stored as private HTML snapshots and optionally emailed as a short summary. See [docs/reports.md](docs/reports.md). |
| **Portal** | An Overview, an Issues page, an Assets page (with tag and API filters), a Lookalikes page and a Reports page, in light and dark themes. |
| **Portal** | A Home feed (all activity and my tasks), an Overview with a 1/3/12 month score history, an Issues list with one row per risk and a detail page per issue, an Assets page (Active/Inactive tabs, tag filters, bulk tag and rescan up to 50) a Lookalikes page and a Reports page, in light and dark themes. |

The scan pipeline is fixed on purpose: amass + subfinder → dnsx → naabu → nmap → httpx → katana +
gau → vigil → mantis. There is no per-tool plug-and-play; see [Scope and safety](#scope-and-safety).

## Install (Linux, Docker)

```bash
git clone https://github.com/TyrusRC/limes && cd limes
sudo ./install.sh          # -n for non-interactive
```

`install.sh` creates `.env` from `.env.example` with fresh random secrets and memory limits sized
to the host. Review it before continuing, and set `PGBOUNCER_TAG` to a tested
`edoburu/pgbouncer` tag. Compose refuses to start while it is empty.

Limes is then served over plain HTTP at `http://localhost:8082`, on this machine only
(`LIMES_BIND=0.0.0.0` and `LIMES_BIND6=::` in `.env` serve other hosts, and `LIMES_HTTP_PORT` changes the port; the IPv6 loopback is published too because `localhost` resolves to it first on many hosts). TLS is
optional: `make certs`, then `make up HTTPS=1`, and Limes is also at `https://<host>` (443,
`LIMES_HTTPS_PORT`). Every container runs under the compose project `limes`
(`docker compose ps`). Create the first admin user with `make username`.

## Configuration

Settings are environment variables in `.env`. The ones you are most likely to touch:

| Variable | Default | What it does |
|---|---|---|
| `LIMES_BIND` / `LIMES_BIND6` / `LIMES_HTTP_PORT` / `LIMES_HTTPS_PORT` | `127.0.0.1` / `::1` / `8082` / `443` | Where the plain HTTP proxy (and the optional TLS proxy) listen. `LIMES_BIND=0.0.0.0` serves other hosts; the login is then in clear text, so add TLS. |
| `DOMAIN_NAME` / `LIMES_PUBLIC_SCHEME` | `localhost:8000` / `http` | Host and scheme of the links Limes puts in chat notifications (`http` or `https`). Set `https` when you turn TLS on. |
| `LIMES_CONTINUOUS_SCANS` | `true` | Rediscover owned roots on their cadence. `false` stops all automatic scans and monitoring. |
| `LIMES_ATTRIBUTION_AUTO_CONFIRM` | `true` | Auto-confirm candidates that pass ownership scoring and a registry-verified delegation. `false` only flags them. |
| `LIMES_ALERT_WEBHOOK_URL` / `LIMES_ALERT_WEBHOOK_SECRET` | empty | Signed JSON webhook for change alerts (HMAC-SHA256 in `X-Limes-Signature`); both must be set. HTTP is refused unless `LIMES_ALERT_WEBHOOK_ALLOW_HTTP=true`. |
| `LIMES_EMAIL_HOST` / `LIMES_EMAIL_PORT` / `LIMES_EMAIL_USER` / `LIMES_EMAIL_PASSWORD` / `LIMES_EMAIL_USE_TLS` / `LIMES_EMAIL_FROM` | empty / `587` / empty / empty / `true` / `limes@localhost` | SMTP server for the email channel of alert rules. Without a host the channel reports "not configured" instead of failing. |
| `LIMES_ALERT_RULE_<CHANNEL>_PER_HOUR` | in_app `60`, email `30`, slack `60`, webhook `120`, jira `20` | Alert-rule sends per project and channel per hour (`CHANNEL` is `IN_APP`, `EMAIL`, `SLACK`, `WEBHOOK` or `JIRA`). The overflow is counted on the rule and reported once as "N more events"; a down cache pauses rule sends. |
| `LIMES_RANGE_ENUMERATION` | `false` | Expand owned ranges and ASNs into per-IP assets with reverse DNS and InternetDB lookups. See [Passive providers](#passive-providers). |
| `LIMES_RANGE_ADDRESS_CAP` | `4096` | Owned addresses allowed per project across ranges and ASNs (1 to 65536). |
| `LIMES_INTERNETDB_DAILY_BUDGET` / `LIMES_PTR_DAILY_BUDGET` | `5000` / `10000` | Daily lookup budgets for range enumeration, shared by all ranges. |
| `LIMES_REPORTS_ENABLED` | `true` | Generate the recurring reports on schedule. Off keeps existing reports and manual generation. |
| `LIMES_LOOKALIKE_ENABLED` | `true` | Generate and check lookalike domains of owned roots. |
| `LIMES_LOOKALIKE_DNS_DAILY_BUDGET` / `LIMES_RDAP_DAILY_BUDGET` | `5000` / `500` | Daily DNS and RDAP lookups for lookalikes, shared by all projects. |
| `LIMES_LOOKALIKE_HTTP` | `false` | One HTTPS GET per registered lookalike a week (title, login form, brand mention). It tells the lookalike's operator someone is watching. |
| `LIMES_FEEDS_OPTIN` | empty | Comma list of opt-in feeds with unclear terms: `blocklist_de`, `cins`. |
| `LIMES_ABUSECH_AUTH_KEY` | empty | abuse.ch key, sent when set (downloads work without one today). |
| `LIMES_SPAMHAUS_DQS_KEY` | empty | Spamhaus DQS key for per-IP ZEN lookups; off when empty, never logged. |
| `LIMES_CLOUD_CHECKS` | `true` | Bucket listing probes (`cloud.open_storage`) for owned roots: at most 72 GETs per root per sweep (S3, Azure Blob, GCS); a root is swept every 20 hours, or after 6 hours if the last sweep failed. 2000 GETs a day in all, and one project gets at most a quarter of that. `false` turns them off. |
| `LIMES_CODE_SEARCH_TOKEN` | empty | GitHub token for code search (`leak.public_code`); off when empty. Sent only in an `Authorization` header to `api.github.com`; never logged or stored. |
| `LIMES_HIBP_API_KEY` | empty | Have I Been Pwned key for domain breaches of owned roots; off when empty, sent only in a header. |
| `LIMES_OIDC_ENABLED` | `false` | Turn on "Sign in with SSO" (OpenID Connect). Needs the four settings below; with any missing, SSO stays off. See [docs/sso.md](docs/sso.md). |
| `LIMES_OIDC_ISSUER` / `LIMES_OIDC_CLIENT_ID` / `LIMES_OIDC_CLIENT_SECRET` | empty | The provider's https issuer URL (discovery is read from `/.well-known/openid-configuration`) and the client registered for Limes. The secret is never logged or shown. |
| `LIMES_OIDC_REDIRECT_BASE` | empty | The public https origin of this site, for example `https://limes.example.com`. The provider must allow exactly `<base>/sso/callback/`. |
| `LIMES_OIDC_SCOPES` | `openid email profile` | Scopes asked for (`openid` is always included). |
| `LIMES_OIDC_ALLOWED_DOMAINS` | empty | Comma list of email domains allowed to sign in. Needs a provider-verified email. Empty: no domain check. |
| `LIMES_OIDC_AUTO_CREATE` | `false` | Create an account at first SSO sign-in. Off: only accounts already linked (or linked by email, below) can sign in. |
| `LIMES_OIDC_DEFAULT_ROLE` / `LIMES_OIDC_DEFAULT_PROJECTS` | `read_only` / empty | Role (`read_only` or `standard`, never admin) and projects (comma list of slugs) given to accounts created by SSO. With no projects listed a new account sees nothing until an admin adds it. |
| `LIMES_OIDC_LINK_BY_EMAIL` | `false` | Link a first SSO sign-in to the one existing local account with the same email, only if the provider says the email is verified and the account is not an admin. |
| `LIMES_LOCAL_LOGIN` | `true` | `false` removes password sign-in (only honoured while SSO is working, so a typo cannot lock everyone out). |

Chat channels (Slack, Discord, Telegram, Lark) are set up in the portal under Notification Settings.

## Common tasks

| Command | What it does |
|---|---|
| `make up` / `make down` | Build and start / stop the stack. `make up HTTPS=1` adds TLS (run `make certs` once); `make up REALTIME=1` adds the certificate watch. |
| `make username` | Create the first admin user |
| `make logs` | Tail service logs |
| `make test` | Run the core test suite in containers |
| `sudo ./update.sh` | Pull, rebuild and restart |

## Passive providers

Scans query free, keyless sources; none of them contacts your targets. Feeds are downloaded once per
publisher cadence, never redistributed, and shown with their credit and date on the Overview:

| Provider | Used for |
|---|---|
| crt.sh | Hostnames under owned roots; other domains sharing your certificates become review candidates |
| Shodan InternetDB | Open ports, CPEs, vulnerability IDs and tags per IP; hostnames on owned IPs become candidates |
| RIPEstat | ASN, prefix and holder per IP; the announced IPv4 prefixes of an ASN you add |
| Spamhaus DROP / ASN-DROP | Listed ranges and ASNs. Contains data from The Spamhaus Project; free for any organisation, credit kept ([terms](https://www.spamhaus.org/blocklists/do-not-route-or-peer/)) |
| abuse.ch Feodo Tracker | Botnet C2 addresses, CC0 ([terms](https://abuse.ch/terms-of-use/)) |
| CISA KEV | Known-exploited CVE markers, CC0 |
| EPSS | Exploit-probability markers by FIRST.org / Empirical Security; attribution requested ([terms](https://www.first.org/epss/faq)) |
| IANA RDAP bootstrap + registry RDAP | Registrar, creation date and abuse contact of lookalike domains (IANA data is CC0) |
| dnstwist (library, Apache-2.0) | Generates lookalike name variants only; none of its web or screenshot features are used |
| Registry RDAP servers | Looked up per domain at the registry named by the IANA bootstrap, within each registry's terms of use (rate-limited, daily budget) |
| Have I Been Pwned (optional, key) | Domain breach counts, CC BY 4.0 |
| Spamhaus DQS (optional, key) | Per-IP ZEN lookups |

Shodan InternetDB is free for non-commercial use; commercial use needs a Shodan enterprise license,
and its terms are only partly published. Limes throttles itself to one request per second, shares
that limit across all workers, and stays inside the daily budgets above. Range and ASN enumeration
is therefore **off by default**: turn it on with `LIMES_RANGE_ENUMERATION=true` once you have checked
the terms for your use. IPv6 prefixes are recorded but not walked address by address.

## Scope and safety

- **Owned only.** Active scans, port scans and the light monitor touch only assets you own. Ranges
  that are private or reserved are refused when you add them and again at every step.
- **Safe contact.** Before Limes connects to a host it resolves the name once, refuses it if any
  answer is a private, loopback, link-local or cloud-metadata address, and then connects only to the
  address it checked, so a name that changes its answer mid-check cannot redirect traffic.
  Certificates are always verified against the hostname. The checks do not use `HTTP(S)_PROXY`.
- **Fixed toolset.** vigil runs by absolute path with a minimal environment and a `PATH` that holds
  only approved tools (nuclei). Before every scan it lists what it can see and refuses to run if
  anything else is visible, because vigil would use any of its supported external tools it finds
  (including exploitation tools such as sqlmap). To approve another tool, change
  `VIGIL_TOOL_ALLOWLIST` and the Dockerfile step together; read the notes in
  `web/limes/integrations/vigil.py` first.
- **Lookalikes: DNS, RDAP and CT only; HTTP only with `LIMES_LOOKALIKE_HTTP`, which tells the
  lookalike's operator someone is watching.** A lookalike is never an asset: nothing scans, crawls or
  monitors it, and "This is ours" only opens the add-asset form for you to confirm. Lookalike names
  are shown as text, never links.
- **Untrusted data.** Finding names, hostnames, banners and logs come from the hosts you scan and are
  escaped everywhere they are shown.

## Upgrading

- The first scheduler ticks after an upgrade that links existing owned roots to scan targets scan
  every previously unlinked root, one per tick and at most two at a time, so expect a burst of scan
  activity.
- `manage.py reclassify_roots` converts old hostname rows that are really registrable roots (for
  example `example.co.uk`). It is idempotent and logs every change. Run it once after upgrading.
- Scheduled tasks `monitor_assets` and `enumerate_ranges` run on the `io` queue; the scheduler locks
  live in Redis. So do the new `refresh_feeds`, `generate_lookalikes`, `lookalike_tick` and `hibp_sync`,
  `poll_ct_api` (every 60 s; it only calls Cert Spotter when `LIMES_CERTSPOTTER_API_KEY` is set) and the
  `drain-events` tick (`monitor_assets` with `events_only`, every 15 s), which drains the event-driven check queue.
- The first run of each new feed and the first lookalike sweep of each root are silent baselines: they
  record what exists and send no alerts. IP reputation, exposed AI services, the leak checks, open cloud storage, dangling-DNS takeover, the MTA-STS/TLS-RPT/BIMI checks and dangling name servers are provisional: they
  appear as issues but do not change any score.
- Tags are now per project. The migration copies each existing global tag into every project that used
  it, and keeps names that cannot be normalised as `tag-<id>`. APIs are a new asset kind (`api`); they
  are found from OpenAPI/Swagger documents on owned hosts and are never scan targets.
- Removed: the PDF scan report, the local LLM service (`make up LLM=1`), the LLM toolkit and stored
  OpenAI/Netlas/Chaos keys, wordlist upload, Swagger docs, the recon notes and the WHOIS and domain-info
  pages. Their tables are dropped by migrations. Discord alert state is stored as JSON instead of pickle.
- Removed: the old results pages (Subdomains, Endpoints, Vulnerabilities, the per-scan detail page), the Targets and
  Organizations pages, subscans, scheduled scans from the UI, the interesting-lookup keywords and the country lookup of
  IP addresses. Start a full scan (port scan, crawl, vigil, mantis) with **Full scan** on an owned root on the Assets
  page, or `POST /api/action/asset/fullscan/`; one scan runs per project at a time. A finding's evidence is in the
  Issues modal, the top-bar search covers assets and issues, and Scan History lists runs with Stop. The tables for
  organizations, interesting-lookup keywords, search history, countries and subscans are dropped by migrations.
  The scan-detail links in old in-app notifications now open Scan History.
- The scan pipeline no longer reads or writes the Subdomain and EndPoint tables, and the migrations drop them. The
  hosts of a scan are hostname assets (each stamped with the scan that saved it); the URLs a scan probed are listed in
  `endpoints.jsonl` in its results folder, which the screenshot, crawl, vigil and nmap stages read. Probe and
  screenshot results go straight onto the host asset. New and missing hosts are change alerts, so the separate
  "Subdomain changes" chat message is gone (its toggle in Notification settings now does nothing). A finding's tags,
  CWE ids and reference links are stored on the finding itself (CVE ids stay linked rows); the migration copies the
  existing ones, and `get_vulnerability` and the Issues evidence return the same data as before. The per-scan
  subdomain and endpoint counts are gone from the scan bar. Links in chat notifications use `LIMES_PUBLIC_SCHEME`
  (default `http`). Per-scan URL files exist only for scans run after this upgrade.
- The DAST tool is installed from `TyrusRC/vigil`. Rebuild the image (`make build`) to pick up the
  `vigil` binary.
- The certificate watch is off by default. `make up REALTIME=1` with `LIMES_CT_WATCH=true` starts it and
  downloads about 157 GB/day (inferred, not measured); read [docs/realtime.md](docs/realtime.md) first.

## Status

Built and merged: inventory and discovery, continuous tracking of added assets, the risk score and
checks, change alerts, waivers, notes and the fix forecast, a native MCP server (Streamable HTTP and
stdio, personal API tokens; see [`docs/mcp.md`](docs/mcp.md)), and the portal in light and dark themes.
The Overview shows the score by category, exposure, certificates, technologies, remediation, discovery,
coverage, top risks and what changed, plus IP reputation and data leakage cards (provisional) and a
Brand card. Discovery and reputation are built too: feeds, KEV/EPSS markers, AI-service and leak
checks, optional breach data, and the lookalike review queue.
Asset tags with per-tag scores and API discovery (provisional checks) are built. Near-real-time monitoring is built too (opt-in certificate watch, event-driven checks, DNS change
detection, live Overview); see [docs/realtime.md](docs/realtime.md).

## Security

Report vulnerabilities privately; see [.github/SECURITY.md](.github/SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
