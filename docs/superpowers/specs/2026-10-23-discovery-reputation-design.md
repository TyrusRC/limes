# Lookalike domains, IP reputation, exploitability markers and new exposure checks

Status: written 2026-10-23; awaiting the user's review. Project 3 of 4 on the UpGuard-gap roadmap approved on 2026-10-17. Every detail is my call unless it is listed under "Decisions for the user".
Builds on `main` at `1af2e8c`: risk checks (`RiskCheck`, `limes/checks/`), the `limes-score-v3` score with waivers, change alerts (`ChangeEvent`, `TrackedIssue`), the light monitor (`limes/monitor.py`), owned ranges (`limes/owned_ranges.py`), and the richer Overview (category cards, Top risks).
Research date: 2026-10-23. Each external fact carries its URL. **(inference)** marks my own conclusions.

## Intent

UpGuard rates ten categories. Limes now shows six (`scoring.CATEGORIES`). The rich-dashboard spec left out IP Reputation, Brand and Data Leakage on purpose, because Limes collects no data for them yet (`2026-10-23-rich-dashboard-design.md`, Non-goals). UpGuard weights IP/domain reputation at 19% and Data Leakage at 3% (https://help.upguard.com/en/articles/3765184-how-are-upguard-s-security-ratings-calculated). It also sells typosquatting monitoring (https://help.upguard.com/en/articles/3824963-what-is-upguard-s-typosquatting-module) and shows CISA KEV and EPSS markers on vulnerabilities (https://help.upguard.com/en/articles/3806262-what-is-upguard-breachsight-s-vulnerabilities-module).

This project fills those gaps using free data, while keeping Limes' rule about contact: owned assets get light checks; third parties get DNS and RDAP lookups and nothing more, unless the operator opts in.

## Scope

### In

| Piece | What it does | Contacts |
|---|---|---|
| **A. Lookalike domains** | Generates typo, homoglyph, TLD-swap and keyword permutations of each owned root. Uses DNS to find which are registered and set up (NS, A/AAAA, MX). Uses RDAP to get the registrar, creation date and abuse contact. Uses CT to see whether a registered lookalike has a certificate. Adds a review queue, alerts, and a generated abuse-report text. | DNS through the configured recursive resolver; RDAP servers; crt.sh. No HTTP to lookalikes by default. |
| **B. IP reputation** | Checks owned IPs, ranges and ASNs against downloaded free blocklists. Becomes `rep.*` risk checks. | Feed publishers only, a few downloads a day. Never the target. |
| **C. Exploitability markers** | Joins the FIRST EPSS score and the CISA KEV flag to every finding with CVE ids, and to InternetDB banner CVEs (shown as unverified). Shown as markers, used as a tie-break in Top risks, and available as a filter. | Two daily downloads. |
| **D. Exposed AI/LLM services** | One or two read-only GETs, through `safe_fetch`, to owned IP:port pairs that InternetDB or naabu has already seen open on a known AI port. Fingerprints Ollama, OpenAI-compatible servers (vLLM, LM Studio, LocalAI, LiteLLM), Triton, Gradio, Jupyter and Ray, and records whether each one answered without authentication. | Owned IPs only, ports already known. |
| **E. Data leakage, part 1** | A pure scan of the client JavaScript the crawl already downloaded (`code_artifacts/`). Flags a Supabase secret or `service_role` key shipped to browsers (critical). Records Supabase, Firebase and S3 backend references as informational dependencies. HIBP domain search is available only with the operator's own key. | None for the JS scan. HIBP only with a key. |

### Out (non-goals)

- **Testing whether a Supabase, Firebase or S3 backend is actually open.** Finding the config in JS is easy, but it does not prove exposure. Supabase publishable/anon keys are meant to be public, and Row Level Security decides access (https://supabase.com/docs/guides/api/api-keys). Firebase API keys "only identify your Firebase project", and Security Rules protect the data (https://firebase.google.com/docs/projects/api-keys). Proving exposure would mean querying data on a third-party-hosted backend with a key. That is out of scope. This feasibility limit is a fact, not a gap left to fill later.
- **Screenshots, page hashing, LSH or any crawl of lookalike sites.** dnstwist can do these only with `--lsh` / `--phash` (https://github.com/elceef/dnstwist). Limes never turns them on.
- **Sending abuse reports.** Limes writes the text, and a person sends it.
- **Changing the score model.** Every new check ships *provisional* (see Scoring), so `limes-score-v3` stays numerically unchanged.
- **A Brand score or grade.** Lookalikes are not owned assets, so a brand grade would have no assets to roll up. Brand is a card and a queue, not a category score.
- **Domain reputation (Spamhaus DBL, URLhaus hosts) by default.** Both need a key; see opt-in feeds.
- **Paid identity-breach, infostealer, paste or dark-web feeds.** These stay on the roadmap's paid-connector list.
- **The SSLBL certificate-SHA1 match.** It needs a certificate fingerprint that the TLS observer does not collect today, and an owned host serving a malware C2 certificate is very rare **(inference)**. This is backlog.
- **certstream / a local CT mirror.** That is the upgrade path named in `limes/intel/http.py`, not this project.

### Anti-goals (a failure even if it works)

- **Scanning or attacking a lookalike site.** No port scan, nuclei, assay, crawl, screenshot or path probe ever runs on a lookalike. This is guaranteed by construction: lookalikes are a separate model, never `Asset` rows, so no pipeline stage can select them (see Data model).
- **Treating a lookalike as owned.** "This is ours" (a defensive registration) does not promote the row. It opens the existing manual add-asset flow, which the user confirms and which is audited.
- **Flooding DNS or RDAP.** Hard daily budgets (`ratelimit.take_daily`, fails closed), per-provider spacing (`ratelimit.reserve`), a per-tick share (`ratelimit.per_tick`), and a capped candidate set per root.
- **Redistributing feed data.** Raw feed files stay on the artifact volume and are never served by the UI, the API, exports or the MCP server. Only matches against the project's own assets are shown.
- **Breaking feed terms.** Each feed's attribution is shown where its data appears. Download cadence stays at or below the publisher's limit. Feeds whose terms are unclear or need a key are off by default.
- **Secrets in logs.** HIBP, DQS and abuse.ch keys come from the environment only. A DQS key sits inside the DNS query name, so every log line and error that could hold a query name redacts it. HTTP errors log the status, never the request headers.
- **Hostile data breaking the page.** Lookalike names (including IDN homoglyphs), RDAP strings, feed comments, HTTP titles and JS-extracted URLs are all attacker-controlled. They are length-capped on write and escaped on render. Lookalike domains are shown as text, never as links, so nobody clicks into a phishing site from Limes. Unicode forms are shown next to their punycode form.
- **A first sweep flooding the channels.** A root's first lookalike sweep and a feed's first evaluation are recorded silently as a baseline, following the existing first-sync rule.
- **A provisional check moving the headline score or the assessed set.** See Scoring; a test pins both.

## Research: data sources, licences and limits

### Lookalike generation: dnstwist as a library

- `dnstwist` 20250130 is the latest PyPI release, uploaded 2025-01-30. Licence: Apache-2.0. `requires_dist` holds only optional `full` extras, so a bare install has no dependencies (https://pypi.org/pypi/dnstwist/json, https://pypi.org/pypi/dnstwist/20250130/json, https://github.com/elceef/dnstwist). Limes is Apache-2.0 too (`LICENSE`), so the licences are compatible.
- The release is about 21 months old. That is fine for a generator, because permutation algorithms don't go stale **(inference)**. Pin it exactly (`dnstwist==20250130`), following the repo's pinning style.
- dnstwist.py defines `class Fuzzer` with `__init__(self, domain, dictionary=[], tld_dictionary=[])`, `generate()` and `permutations()`. Its fuzzers are addition, bitsquatting, cyrillic, homoglyph, hyphenation, insertion, omission, plural, repetition, replacement, subdomain, transposition, vowel-swap, dictionary, tld-swap and various (https://raw.githubusercontent.com/elceef/dnstwist/master/dnstwist.py).
- **Decision:** use only `Fuzzer`, which makes no network calls. Never call `dnstwist.run()`, because it does its own DNS with its own threads and has the optional HTTP/LSH paths. Limes does the lookups itself, through its own budgets. This is the "installed dependency" rung: writing a native generator would duplicate roughly 400 lines of well-tested permutation code **(inference)**.
- **Measured volume** (run offline on 2026-10-23, with an 8-word dictionary and an 8-TLD list). Unfiltered output was 2,015 for `example.com` and 15,463 for `acmecorporation.com`. Homoglyph combinations account for almost all of it (15,005). Keeping only homoglyphs at edit distance 1 from the original label gives **334**, **706** and **254** (`mybrand.co.uk`). So: homoglyphs are limited to one substitution, and `MAX_CANDIDATES_PER_ROOT = 1000` applies (`NOTE:` ceiling; the upgrade path is a per-root setting).

### Registration and setup: DNS and RDAP

- DNS goes through the existing resolver path (`collect._resolve`, dnspython). Each candidate costs one `NS` query. NXDOMAIN or no NS means not delegated. A registered candidate then costs `A`, `AAAA` and `MX` queries. A registered domain with no delegation (for example `serverHold`) looks unregistered over DNS, so RDAP is the authority for "registered" **(inference)**.
- RDAP: rdap.org is a bootstrap redirector, rate-limited by Cloudflare to "a maximum of 10 requests in 10 seconds", and it tells heavy users to "use a proper RDAP client that uses the bootstrap files instead" (https://about.rdap.org/). The bootstrap mechanism is RFC 9224 (https://www.rfc-editor.org/rfc/rfc9224). **Decision:** fetch the IANA DNS bootstrap file (https://data.iana.org/rdap/dns.json) weekly, and query each TLD's RDAP server directly, spaced per server with `ratelimit.reserve('rdap:<host>', 2.0, …)` and a daily budget. Per-registry RDAP limits are not published in one place, so a conservative 1 request per 2 s per server is my choice **(inference)**.
- RDAP is used only for candidates that DNS shows as delegated, plus a monthly re-check of those. The abuse contact is read from the entity with role `abuse` (builder verifies against real responses). WHOIS on port 43 is never used.

### CT lookalikes

- crt.sh is already a provider (`limes/intel/crtsh.py`, 5 s spacing). Its page documents no wildcard or usage limits (https://crt.sh/), so keyword search is best-effort **(inference)**.
- **Decision:**
  - For every *registered* lookalike, one exact query `?q=<lookalike>&output=json&exclude=expired` gives a "has a certificate" signal, which shows phishing readiness. This one is reliable.
  - Once a day per owned root, one keyword query `?q=%25<brand label>%25` adds CT-seen names that the generator missed, matched on whole labels or edit distance ≤ 2 to the brand label (roadmap rule: whole-label brand matches, never substrings). When it times out, the result is "no data", never "no lookalikes".

### IP reputation feeds

| Feed | URL | Terms | Cadence | Default |
|---|---|---|---|---|
| Spamhaus DROP v4 / v6 (eDROP merged into DROP on 2024-04-10) | https://www.spamhaus.org/drop/drop_v4.json, https://www.spamhaus.org/drop/drop_v6.json | Free "regardless of size or business type". Credit "must be given to The Spamhaus Project", and "the date and copy text should remain with the file" (https://www.spamhaus.org/blocklists/do-not-route-or-peer/). Merge: https://www.spamhaus.org/resource-hub/network-security/spamhaus-drop-and-edrop-to-become-a-single-list | Changes daily. "should not be downloaded from our website more than once per day" (same page). | **On**: fetched once every 24 h |
| Spamhaus ASN-DROP | https://www.spamhaus.org/drop/asndrop.json | Same as DROP | Same | **On**: matched against owned `asn` assets |
| abuse.ch Feodo Tracker (botnet C2 IPs, recommended list) | https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json | Feodo Tracker and SSLBL are "free to use without limitations according to Creative Commons principles (CC0)", "for both commercial and non-commercial purposes" (https://abuse.ch/terms-of-use/) | Regenerated every 5 min. The page currently says the datasets "are currently empty" (https://feodotracker.abuse.ch/blocklist/) | **On**: every 6 h. A cheap, low-yield feed **(inference)** |
| abuse.ch SSLBL botnet C2 IPs | https://sslbl.abuse.ch/blacklist/sslipblacklist.csv (not the `_aggressive` list, which "will cause false positives") | CC0 (as above) | Every 5 min; "not fetch it more often than every 5 minutes" (https://sslbl.abuse.ch/blacklist/) | **On**: every 6 h |
| blocklist.de all | https://lists.blocklist.de/lists/all.txt | No licence stated; "to be used at your own risk" (https://www.blocklist.de/en/export.html). The terms page excludes download "bei zu großem Volumen" (too large a volume) from free use (https://www.blocklist.de/en/terms.html) | Every 30 min. Covers only the last 48 h of reports | **Off** (opt-in): terms unclear |
| CINS Army | http://cinsscore.com/list/ci-badguys.txt | "parse and use in any way you see fit". Commercial use and redistribution are not addressed (https://cinsscore.com/) | Not stated | **Off** (opt-in): unclear terms and a plain-HTTP URL (integrity) |
| abuse.ch URLhaus (domain/URL reputation) | API v2 exports with an Auth-Key | An `Auth-Key` is required; commercial users "may require a paid subscription" (https://urlhaus.abuse.ch/api/) | Every 5 min | **Off**: needs a key |
| Spamhaus ZEN / DBL over DNS | DQS with a key | Free public mirrors are "free of charge for non-commercial use by small and medium sized organisations", from "a recursive resolver run on your own network or from a public resolver which supports ECS" (https://www.spamhaus.org/blocklists/dnsbl-fair-use-policy/). Public resolvers get `127.255.255.254`; too many queries get `127.255.255.255` (https://www.spamhaus.org/faqs/dnsbl-usage/). A free DQS account is for "non-commercial entity or a small business with low query volumes" (https://www.spamhaus.com/data-access/free-data-query-service/) | One query per owned IP per day | **Off**: only with `LIMES_SPAMHAUS_DQS_KEY`. Both error codes are treated as `error` (not assessed), never as a listing |
| FireHOL blocklist-ipsets | https://github.com/firehol/blocklist-ipsets | An aggregator; "a few of these lists may have special licences attached" | Daily | **Not used**: Limes fetches the primary sources instead, each with its own terms |

An owned organisation running Limes for its own security is probably not "non-commercial" in Spamhaus' DNSBL sense. That is why the DNSBL path is key-only and off, while DROP (explicitly free for any organisation) is on **(inference)**.

abuse.ch's terms say "Access to the abuse.ch Platforms is provided only to … Authenticated Users" (https://abuse.ch/terms-of-use/), yet the Feodo and SSLBL pages publish plain download paths. **Decision:** send `Auth-Key` when `LIMES_ABUSECH_AUTH_KEY` is set. The builder checks whether the downloads work without it, and if not, both feeds are off until a key is set.

### Exploitability data

- **EPSS:** `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`. The URL "does not change" and "redirects". The file is gzip CSV with `cve,epss,percentile` and a `#` header comment holding the model version and date. Scores are "published daily, free of charge, with no registration required" (https://www.first.org/epss/data). "Attribution is requested when EPSS data is used in publications or products" (https://www.first.org/epss/faq). No licence is named, so the data is shown with attribution and never redistributed.
- **CISA KEV:** `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`, with schema `…/known_exploited_vulnerabilities_schema.json` (https://www.cisa.gov/known-exploited-vulnerabilities-catalog). Licence: CC0 1.0 (https://www.cisa.gov/sites/default/files/licenses/kev/license.txt). The page states no cadence, so Limes fetches daily with `If-Modified-Since`.

### AI/LLM service fingerprints

| Service | Default port | The one read-only GET, and what it shows | Source |
|---|---|---|---|
| Ollama | 11434 | `GET /api/tags` returns `{"models": [...]}` when unauthenticated. `/api/version` returns `{"version"}` | https://raw.githubusercontent.com/ollama/ollama/main/docs/api.md |
| vLLM and other OpenAI-compatible servers | 8000 for vLLM | `GET /v1/models`: 200 with a list means no key; 401 means a key is set. `--api-key` protects only `/v1`, `/v2` and `/inference` | https://docs.vllm.ai/en/latest/cli/serve/ |
| NVIDIA Triton | 8000 HTTP, 8001 gRPC, 8002 metrics | `GET /v2/health/ready` returns 200 when ready | https://docs.nvidia.com/deeplearning/triton-inference-server/user-guide/docs/getting_started/quickstart.html |
| Gradio | 7860 | `GET /config` (app config JSON) | https://www.gradio.app/guides/environment-variables |
| Jupyter Server | 8888 | `GET /api` returns the version and "does not require any authentication". So exposure is proven by a second GET, `/api/kernels` (200 = no auth) | https://jupyter-server.readthedocs.io/en/latest/developers/rest-api.html |
| Ray dashboard / Jobs API | 8265 | `GET /api/version`. Its Jobs API has no authentication (CVE-2023-48022, exploited as ShadowRay) | https://www.bleepingcomputer.com/news/security/hackers-exploit-ray-framework-flaw-to-breach-servers-hijack-resources/ |

### HIBP (optional)

`GET https://haveibeenpwned.com/api/v3/breachedDomain/{domain}` with header `hibp-api-key`. It needs a paid Core or Pro subscription and a verified domain (otherwise 403). It has "no formal rate limit", but callers should query only after new breaches appear. The data is CC BY 4.0, and Have I Been Pwned must be named as the source with a link. The user agent must describe the app accurately (https://haveibeenpwned.com/API/v3).

## Design

### Scoring: provisional checks and two new categories

- `catalogue.Check` gains a `provisional` field, default `False`. Every check added by this project is `provisional=True`. This mirrors UpGuard: new checks start with zero score impact and a "provisional" label (https://help.upguard.com/en/articles/6708571-what-are-provisional-risks).
- `scoring` gets one helper, `points(key, severity)`, which returns 0 for a provisional check. `_score`, `_rows`, `forecast` and `dashboard.activity.top_risks` use it instead of `PENALTY[...]`. Provisional keys are also left out of the `CEILING` worst-severity term.
- **`assessed_assets` ignores provisional checks.** Otherwise an IP whose only fresh result is `rep.*` would become "assessed at 950" and shift the P10. A test pins this, along with "a project with provisional fails has the same headline as without them".
- Provisional issues still flow through `current_issues`, so `TrackedIssue`, the Issues page, waivers and events all work on them, with 0 points and a "Provisional" badge.
- `VERSION` stays `limes-score-v3`: the headline is numerically unchanged for every input. Promoting a check later (`provisional=False`) changes the model and bumps it to `limes-score-v4` (Decisions for the user).
- `CATEGORIES` gains `reputation` (label "IP Reputation") and `data_leakage` ("Data Leakage"). `category_of` and `category_q` pick them up from the check group without changes. `category_scores` reports a category whose checks are all provisional as `{'provisional': True, 'score': None, …}`, so its card shows issue counts and "Provisional, not scored", never a perfect 950. This follows the rich-dashboard anti-goal. `ScoreSnapshot.categories` stores `None` for it.
- Exposed AI services join the existing `network` group, because they are exposed services like `net.exposed_redis`. As provisional checks they cost nothing inside a scored category, which still reconciles with the headline.
- There is no `brand` category (see Out).

### New check ids (catalogue)

| Id | Group | Severity | Applies to | Fails when |
|---|---|---|---|---|
| `rep.listed_drop` | reputation | 3 | owned ip, cidr | the address or range overlaps a DROP entry |
| `rep.listed_asndrop` | reputation | 3 | owned asn | the ASN is in ASN-DROP |
| `rep.listed_c2` | reputation | 4 | owned ip | Feodo or SSLBL lists the IP as botnet C2 (a likely compromise) |
| `rep.listed_attacker` | reputation | 2 | owned ip | an opt-in attacker list (blocklist.de, CINS) lists it |
| `rep.dnsbl_listed` | reputation | 2 | owned ip | an opt-in DQS ZEN answer is in `127.0.0.0/24` |
| `net.exposed_ollama` | network | 3 | owned ip:port | `/api/tags` answers without authentication |
| `net.exposed_openai_api` | network | 3 | owned ip:port | `/v1/models` returns 200 with a model list |
| `net.exposed_triton` | network | 2 | owned ip:port | `/v2/health/ready` answers |
| `net.exposed_gradio` | network | 2 | owned ip:port | `/config` is Gradio JSON |
| `net.exposed_jupyter` | network | 4 | owned ip:port | `/api/kernels` returns 200 |
| `net.exposed_ray` | network | 4 | owned ip:port | the Ray dashboard API answers |
| `leak.supabase_secret_key` | data_leakage | 4 | owned host (crawl) | client JS contains `sb_secret_…`, or a JWT whose decoded payload has `role: service_role` |
| `leak.hibp_breach` | data_leakage | 2 | owned root | (opt-in) HIBP lists addresses at the domain in a breach published within 365 days |

- The `net.exposed_` prefix makes the AI checks immediate under the existing `events.is_immediate` rule with no code change. `rep.*` is added to that rule.
- Each `rep.*` result carries its evidence: feed, matching entry (CIDR or SBL id), the feed's own timestamp, and `fetched_at`.
- Each AI result carries port, path, status, server version and model count, never the model list in full.
- The leak result carries host, artifact URL, the key's shape (`sb_secret_…4f2a`) and never the key itself.
- Stale data rule, following the risk-checks spec: if a feed's last good fetch is older than 3 × its cadence, its checks write `error` (not assessed), never `pass`.

### Data model (new rows; one migration per app)

- `Lookalike(project, root → Asset (owned_root), domain ascii/punycode, unicode, fuzzers JSON, source 'permutation'|'ct', status, registered bool|null, dns JSON {ns,a,aaaa,mx}, has_mx bool, rdap JSON {registrar, created, abuse_email, statuses} (strings capped at 200), ct JSON {count, first_seen, last_seen}, http JSON|null (opt-in only), first_seen, last_checked, next_check, decided_by, decided_at, note)`, unique on `(project, domain)`.
  - Statuses: `unchecked → unregistered | registered`. Then the user decisions `watching`, `ignored` (remembered, never re-raised), `ours` (hands off to manual add-asset) and `reported` (an abuse report was generated, with its date). `gone` means it was registered once and no longer resolves or exists in RDAP.
  - **It is not an `Asset`.** The candidate tier means "possibly ours, confirm to scan" (roadmap Scope tiers). One mis-click there would start active scans on someone else's server. A separate table keeps every stage selector (`scored_assets`, `monitored`, `_web_hosts`, `due_assets`, `may_attack`) blind to lookalikes without adding a single guard.
- `FeedState(name unique, url, fetched_at, last_good_at, etag, last_modified, sha256, entries, status, error ≤300)`. The parsed feed is kept on the artifact volume at `LIMES_RESULTS/feeds/<name>` (one copy, replaced on each good fetch). It is never served.
- `CveIntel(cve unique, epss float|null, percentile float|null, epss_date, kev bool, kev_added date|null, kev_due date|null, kev_ransomware bool|null, updated_at)`. It is filled only for CVE ids Limes already holds (`CveId.name` ∪ InternetDB `vulns` on owned IPs), so it stays bounded.
- `DomainBreach(project, root → Asset, breach_name, addresses int, breach_date, published, first_seen)`, used only with the HIBP key. **No email aliases are stored** (data minimisation); only counts per breach.
- `RiskCheck` is reused for every new check. `ChangeEvent` is reused, with new kinds.

### Events (`events.KINDS`)

- New kinds:
  - `lookalike_new`: a lookalike became `registered`.
  - `lookalike_active`: a watched lookalike gained MX, an A record or a certificate.
  - `breach_new`: a new HIBP breach name for a root.
- Reputation, AI and leak changes need no new kinds. They are `RiskCheck` rows, so `sync_issues` already emits `issue_new`, `issue_fixed` and `issue_regressed` for them.
- Immediacy:
  - `rep.*` (any severity), `lookalike_active` (on a watched or new row), and `lookalike_new` when RDAP creation is within 30 days **and** it has MX or a certificate (phishing-ready) are immediate.
  - Other `lookalike_new` events and `breach_new` go to the digest.
  - The existing 10-per-hour cap still applies.
- A root's first lookalike sweep and the first evaluation of each feed are silent baselines. They follow the `IssueSyncState` pattern, adding a `lookalike_baselined_at` per root (stored on `IssueSyncState.roots`).

### Tasks (IO queue, each in `celery_routing.TASK_PLAN` and the beat schedule)

| Task | Beat | Lock / budget | Work |
|---|---|---|---|
| `refresh_feeds` | 3600 s | `tick_lock('refresh_feeds')`; per-feed cadence from the table above, enforced via `FeedState.fetched_at` | Conditional GET (ETag / If-Modified-Since). 30 s timeout. Size cap of 50 MB decompressed (`NOTE:` ceiling). Strict parse: only valid IPs, CIDRs, ASNs and CVEs are kept, and a parse that yields 0 entries from a previously non-empty feed is rejected as a bad fetch. Then calls `evaluate_reputation` and `refresh_cve_intel` when their inputs changed. Not a contact with targets; uses `intel.http`-style polite fetches with `User-Agent: Limes-ASM`. |
| `evaluate_reputation` | after feeds, and from `monitor.check_asset` for an IP | none (no network) | Matches owned ip, cidr and asn assets against the parsed feeds (`ipaddress` networks; owned sets are small) and writes `rep.*` `RiskCheck` rows. |
| `refresh_cve_intel` | after feeds | none | Upserts `CveIntel` for held CVE ids. |
| `generate_lookalikes` | 86400 s | `tick_lock` | Runs `Fuzzer` per owned root (with tldextract for the registrable split; it is already a dependency), the one-substitution homoglyph filter and `MAX_CANDIDATES_PER_ROOT`. Inserts new `unchecked` rows. Never deletes decided rows. |
| `lookalike_tick` | 60 s, expires 55 | `tick_lock('lookalike_tick')`; `take_daily('lookalike_dns', LIMES_LOOKALIKE_DNS_DAILY_BUDGET=5000)`; `take_daily('rdap', LIMES_RDAP_DAILY_BUDGET=500)`; `ratelimit.per_tick` share; `reserve('rdap:<host>', 2.0)`; 45 s tick budget | Picks the rows due soonest. Unregistered rows are re-checked every 7 days, registered and watched rows daily (DNS) and monthly (RDAP); `ignored` rows are re-checked every 30 days so that `gone` can be detected. Runs the DNS checks, then RDAP and CT for registered rows, and records the events. |
| `lookalike_http` (opt-in) | inside `lookalike_tick` | `take_daily('lookalike_http', 50)` | See "Contact with lookalikes". |
| AI probes | inside `monitor.check_asset` (IPs) and the `run_checks` IP loop | the existing `RUN_BUDGET`, `safe_fetch.Deadline`, and at most 6 ports per IP | Covers only ports in `AI_PORTS` that the existing port union already shows open (`collect.ports_for_ip`). |
| Leak JS scan | inside `code_audit`, after mantis | none | A pure regex and JWT-decode pass over `code_artifacts/`. Writes `leak.*` on the owned host the artifact came from (`crawl.artifact_source_url`). Backend references go into `Asset.enrichment['backends']` (informational). |
| `hibp_sync` (opt-in) | 86400 s | `take_daily('hibp', 50)` | Calls `/latestbreach`, then `breachedDomain` for each verified owned root only when the latest breach changed or 7 days have passed. |

Volume check: 10 roots × about 700 candidates is 7,000 rows. Unregistered rows on a 7-day rotation need about 1,000 NS queries a day. Registered rows, typically a small share **(inference)**, add 4 queries each a day. That fits the 5,000/day default with headroom for the first sweep, which spreads over a few days by design.

### Contact with lookalikes (third parties)

- **Default:** DNS through the configured recursive resolver, RDAP to registries, and crt.sh. Limes opens no socket to a lookalike's own IP. DNS reaches the lookalike's authoritative nameserver only through the recursive resolver, as any visitor's lookups do. This is accepted, and documented in the README.
- **Opt-in (`LIMES_LOOKALIKE_HTTP=true`, off by default):** for registered lookalikes with an A record, at most once per 7 days, within a 50/day budget:
  - one `GET https://<lookalike>/` through `safe_fetch.resolve_vetted` + `pinned_get` (public IP only, pinned, `HOST_DEADLINE`);
  - redirects are not followed; only the `Location` host is recorded;
  - the body is capped at 256 KB;
  - Limes records the status, title, whether the page contains the brand label, and whether it has a password field;
  - this path must not go through `scope.may_attack` or any scan tool, and it sends the project's scan identity User-Agent.
  - Doing this tells the operator of the lookalike that someone is watching. The README states this and is the reason it is off **(inference)**.

### Abuse report text

- From a `Lookalike` row, Limes fills a plain-text template:
  - the owned brand domain;
  - the lookalike (punycode and unicode);
  - the fuzzer type;
  - RDAP registrar and creation date;
  - DNS records and MX;
  - CT certificate ids and dates;
  - opt-in HTTP evidence;
  - the reporter fields from the project.
- It is addressed to the RDAP abuse email when present, else the registrar.
- The page shows it in a read-only textarea with a copy button. Generating it sets `status=reported` and the date. Limes never sends mail.

### UI surfaces

- **Inventory → Lookalikes** (new page, follows the restyle list pattern):
  - the table shows the domain as text (punycode, with unicode and an IDN badge), fuzzer, registered, age from RDAP creation, registrar, MX, certificate, A, status and first seen;
  - filters: status, registered, MX, age < 30 days;
  - actions: Watch, Ignore, This is ours (opens the add-asset form prefilled; nothing is promoted automatically), Abuse report;
  - every action is audited.
- **Issues:**
  - the `category` filter accepts `reputation` and `data_leakage`;
  - a Provisional badge;
  - KEV and EPSS columns (EPSS shown as a percentage with its percentile);
  - a "Known exploited" filter;
  - the issue detail lists CVE ids with both markers.
- **Overview:**
  - the category cards gain IP Reputation and Data Leakage, shown in their provisional form;
  - a new **Brand** card shows registered lookalikes, new in 30 days, phishing-ready (MX or certificate), awaiting review, and links to the Lookalikes page;
  - **Top risks** sort by points, then KEV, then EPSS (descending), then age, and show a KEV badge.
  - Points come first, so the list still explains the score; KEV and EPSS break ties.
- **Asset detail (IP):**
  - a Reputation section (feed, entry, listed since, attribution);
  - an "Unverified CVEs (InternetDB banner)" list with KEV and EPSS markers, clearly marked unverified and not scored, which follows the roadmap's noise rule.
- **Attribution** appears wherever the data is shown: "Contains data from The Spamhaus Project (date)", "EPSS by FIRST.org / Empirical Security", "abuse.ch", "CISA KEV", and "Have I Been Pwned" with a link.
- There is no settings page. Like the alert webhook, everything is configured by environment variables:
  - `LIMES_LOOKALIKE_ENABLED` (default true);
  - `LIMES_LOOKALIKE_DNS_DAILY_BUDGET`, `LIMES_RDAP_DAILY_BUDGET`;
  - `LIMES_LOOKALIKE_HTTP` (default false);
  - `LIMES_FEEDS_OPTIN` (for example `blocklist_de,cins`);
  - `LIMES_ABUSECH_AUTH_KEY`, `LIMES_URLHAUS_AUTH_KEY`, `LIMES_SPAMHAUS_DQS_KEY`, `LIMES_HIBP_API_KEY`.
  - Each key-gated feature is off when its key is unset.
  - `.env.example` lists the names only.

## Constraints

- Every automatic contact with an owned target goes through `safe_fetch` (resolved once, vetted, pinned). The AI probes add no new connection type; they reuse `pinned_get` on a non-default port.
- Feed and provider fetches never touch targets. They use polite single requests with timeouts, within the publisher's cadence.
- Anything beyond DNS/RDAP/CT toward a third party needs operator opt-in.
- Tests use no network: feeds, RDAP, DNS and HTTP are injected fixtures, following the existing observer pattern. One focused test per behaviour that can break:
  - homoglyph filter and cap;
  - NS-based registration and the RDAP override;
  - budget exhaustion stops the tick;
  - first sweep is silent;
  - DROP CIDR overlap for ip and cidr assets;
  - stale feed gives `error`;
  - a zero-entry fetch is rejected;
  - provisional checks leave the headline and assessed set unchanged;
  - KEV/EPSS tie-break order;
  - Jupyter needs the second GET;
  - the JWT `service_role` decode, with the key never stored;
  - a DQS key is redacted in logs;
  - a hostile RDAP or IDN string is escaped;
  - lookalikes never appear in `scored_assets`, `monitored` or `due_assets`.

## Decisions for the user (each has my default; silence means the default)

1. **Score impact.** All new checks start provisional, with no change to `limes-score-v3`. *Default:* after about four weeks of real data, promote `net.exposed_jupyter`, `net.exposed_ray`, `net.exposed_ollama`, `net.exposed_openai_api`, `rep.listed_c2` and `leak.supabase_secret_key` together as `limes-score-v4`. The rest of `rep.*` stays provisional, because blocklist hits on shared or cloud IPs are noisy **(inference)**. KEV and EPSS never change points.
2. **Optional keyed features** (HIBP paid key, Spamhaus DQS, URLhaus, abuse.ch Auth-Key). *Default:* off; each turns on by itself when its key is set.
3. **Feeds with unclear terms** (blocklist.de, CINS). *Default:* off, available through `LIMES_FEEDS_OPTIN`.
4. **HTTP to lookalike sites.** *Default:* off.

## Left to the builder

- Exact help text and wording, the abuse-report template, and column order.
- `AI_PORTS` beyond the table (for example ComfyUI 8188, LiteLLM 4000, Open WebUI), as long as each has a documented read-only fingerprint path.
- The RDAP JSON paths for registrar, abuse email and creation date (RFC 9083 events and entities), checked against real responses from two or three TLDs.
- Whether the abuse.ch downloads need the Auth-Key today. Turn the feeds off if they do and no key is set.
- The DROP NDJSON trailer line (metadata/copyright). Keep it with the stored copy, as Spamhaus asks.
- How tldextract obtains its suffix list in the container (bundled snapshot preferred over a runtime fetch).
- Query shapes, migrations, serializers, and the Exposure card marking AI ports.
