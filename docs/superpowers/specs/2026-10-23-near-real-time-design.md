# Near-real-time: certificate watch and event-driven checks

Status: draft written 2026-10-23, waiting for the user's review. Builds on `main` at `1af2e8c`. This is project 4 of the 4-project roadmap drawn from the UpGuard comparison. The others are tracking what you own, the richer dashboard, and discovery and reputation.

Everything below is my call unless marked otherwise. **(inference)** marks reasoning that isn't stated in a cited source. Every external fact has a URL.

## Intent

Limes should notice new certificates, subdomains and exposure within minutes, not on the next cadence tick.

UpGuard's own "real-time" is a daily scan cycle whose score is recomputed as data lands: active domains are rescanned daily and inactive ones monthly, and "Rescan" results arrive "within a day" (https://help.upguard.com/en/articles/3800663-how-frequently-does-upguard-scan-websites, https://help.upguard.com/en/articles/3833967-how-to-rescan-a-domain-in-upguard-breachsight). Its new-domain and new-IP alerts have existed since 2022 (https://www.upguard.com/releases/notifications-for-when-new-domains-and-ips-are-detected). So beating UpGuard on latency is honest and reachable for the signals that are published continuously, which means Certificate Transparency and DNS. It is not reachable for the signals that need scanning.

## What "near real time" can honestly mean

### Targets (measured, shown on the new Real-time card)

| # | Signal | Target | Holds when |
|---|---|---|---|
| T1 | A new certificate naming an owned root, an owned hostname or a watched lookalike appears in a CT log, and Limes records a `CertSighting` and its change event | **≤ 15 min p95** from the log publishing the entry | The CT watch is on and healthy |
| T2 | A new owned subdomain from any source (CT, scan, range sweep, manual add) gets its first light check (resolve, InternetDB, TLS, web, exposure) | **≤ 5 min p95** from discovery | The event queue is not over its cap |
| T3 | An immediate alert reaches in-app, chat and webhook | **≤ 60 s p95** from the event row being written | The hourly cap (`ALERT_HOURLY_CAP`, 10 per project) isn't spent |
| T4 | A DNS change (A/AAAA/CNAME delta) on a crown-jewel hostname | **≤ 15 min** | Always (DNS only) |
| T4b | The same on other monitored assets | the monitor's interval: 24 h active, 30 d inactive | Always |
| T5 | A service newly exposed on an owned IP | **≤ the active interval (24 h)**, plus InternetDB's own data age | Always |
| T6 | Degraded mode: a new certificate seen without the watch | Cadence scan interval (24 h crown jewel, 7 d standard) plus crt.sh's ingest lag. With a Cert Spotter API key: about `ceil(roots / 7)` hours per root | The watch is off or degraded |

How each target is measured:
- **T1** is measured from watcher to event: the spool file's mtime to `CertSighting.first_seen_at`. That leg should take ≤ 10 s.
- The upstream leg of T1, from log to certspotter, is not observable per certificate. Its honest proxy is certspotter's own health check ("not falling behind on any log", https://github.com/SSLMate/certspotter/blob/master/man/certspotter.md). The card shows that proxy, not a made-up number.
- **(inference)** `first_seen_at − not_before` would overstate the lag, because CAs often backdate `notBefore`. It is recorded for trend only and labelled as an upper bound.
- **T2 and T3** come from stamps already in the rows: `enqueued_at` against `monitor.checked_at`, and `ChangeEvent.created_at` against `notified_at`.

### What near real time cannot mean here

- **Port changes without scanning.** Exposure comes from Shodan InternetDB, which reflects Shodan's own crawl schedule. **(inference)** That data is days old, not minutes. Minutes-level port detection needs active scanning of owned ranges, which is a non-goal (see the track-owned-assets spec).
- **Names that never get a public certificate.** Internal names, names covered only by a wildcard, and hosts behind a private CA are not in CT, so they are found only by scans, DNS or ranges.
- **"Certificate issued" is not "host live".** Precertificates are logged *before* issuance (RFC 6962 §3.1, https://www.rfc-editor.org/rfc/rfc6962#section-3.1). A host's first check may therefore find nothing yet. The design re-checks it twice (below).
- **A guaranteed upper bound for T1.** A log only promises to merge an entry within its Maximum Merge Delay (RFC 6962 §3, https://www.rfc-editor.org/rfc/rfc6962#section-3). **(inference)** Minutes is typical, not guaranteed.
- **Score recomputation.** The score already moves as soon as a check lands (`sync_issues` after every tick). Nothing changes there.

## Certificate-event source: research

| Option | Facts (cited) | Verdict |
|---|---|---|
| **Public CertStream** (`certstream.calidog.io`) | The server is MIT-licensed (https://github.com/CaliDog/certstream-server). Open issues include "is the server down?" (#114, 2024-02-05), "websocket is closing every minute or so" (#108, 2023) and "full-stream being disconnected at regular interval" (#59), plus 2025 parser crashes (#133, #134) (https://github.com/CaliDog/certstream-server/issues). The author of certstream-server-go wrote it because the hosted demo "wasn't as reliable as I thought it would be … I got disconnects and sometimes other errors" (https://github.com/d-Rickyy-b/certstream-server-go). No terms of use, SLA or rate statement was found; the page body is client-rendered (https://certstream.calidog.io/). There is no replay, so any disconnect is a silent gap **(inference from the websocket-only design)**. | **Rejected.** It is a demo service, gaps are silent, and it would hand every Limes deployment's uptime to a third party. |
| **Self-hosted certstream-server-go** | MIT. It uses about 40 MB RAM, 14.5 Mbit/s and 4–10 % CPU at idle while processing about 250–300 certs/s, and tails every log in Google's list (https://github.com/d-Rickyy-b/certstream-server-go). Static CT support arrived in v1.9.0 (2026-04-03). v1.10.0 (2026-09-13) fixed "excessive tile fetching" and an "off-by-one in Static CT path" (https://raw.githubusercontent.com/d-Rickyy-b/certstream-server-go/master/CHANGELOG.md). It can resume its own log positions, but clients get a live websocket with no replay. | **Not chosen.** It sends every certificate in the world to Limes to filter, at about 300 messages/s through Python. Its static-CT reader is six months old and was still being fixed in September. It is the upgrade path only if keyword-style lookalike matching (not a fixed list) is ever wanted. |
| **Self-hosted certspotter (SSLMate)** | MPL-2.0 (https://github.com/SSLMate/certspotter). It monitors RFC 6962 and static-ct-api logs, every log Qualified/Usable/ReadOnly in the Chrome or Apple lists, and reloads the list periodically. It keeps per-log positions in a state dir, so a restart resumes rather than gaps. A 24 h health check reports a log not contacted or "falling behind". The watchlist is one name per line, and a leading dot means the whole subtree. It is read only at start-up, so a change needs a restart. `-script` runs on `discovered_cert` / `malformed_cert` / `error` with `JSON_FILENAME` (which carries `dns_names`), `TBS_SHA256`, `CERT_SHA256`, `ISSUER_DN`, `NOT_BEFORE_RFC3339`, `LOG_URI` and `ENTRY_INDEX`. `-start_at_end` skips history. Exit is 0 on SIGTERM (https://github.com/SSLMate/certspotter/blob/master/man/certspotter.md, https://github.com/SSLMate/certspotter/blob/master/man/certspotter-script.md). Static-ct-api arrived in v0.19 (2025-05). Since then it gained parallel downloads, per-log rate-limit respect (v0.23), precert/cert dedupe (v0.24) and experimental Prometheus metrics (v0.25.0, 2026-09-13) (https://raw.githubusercontent.com/SSLMate/certspotter/master/CHANGELOG.md). | **Chosen as primary** (opt-in). |
| **Reading CT logs directly** (RFC 6962 `get-entries`, https://www.rfc-editor.org/rfc/rfc6962#section-4.6, plus static-ct-api tiles, https://github.com/C2SP/C2SP/blob/main/static-ct-api.md) | Google's list (https://www.gstatic.com/ct/log_list/v3/log_list.json, timestamp 2026-10-22T13:35:15Z, v95.9, fetched and counted) has 11 operators. It holds 21 usable RFC 6962 logs (2 more read-only, 3 retired) and 59 usable or qualified **tiled** logs (22 usable, 37 qualified). Let's Encrypt made its RFC 6962 logs read-only on 2025-11-30 and shut them on 2026-02-28, so it writes only to static-ct logs, and monitors need static-ct-api clients (https://letsencrypt.org/2025/08/14/rfc-6962-logs-eol.html). | **Rejected** as Limes code: it would mean writing two log-reader protocols and keeping up with log-list churn. certspotter already does exactly this. |
| **Volume: can a small deployment tail all logs?** | About 250–300 certs/s from the certstream-server-go figures above. **(inference)** That is about 22–26 M entries a day. At the quoted 14.5 Mbit/s it is about 157 GB a day, or about 4.7 TB a month, of *inbound* traffic. CPU and RAM are small. | **(inference)** On CPU and RAM, yes. On **bandwidth** only where inbound traffic is unmetered, hence **opt-in**. |
| **crt.sh JSON / public PostgreSQL** | No published fair-use policy. Abusive IPs are blocked. The firewall averages 2 connections/s per client and drops connections beyond 5 in 10 s (operator post, 2024-06-18, https://groups.google.com/g/crtsh/c/niabC5EYW2g). In Feb–Mar 2025, ingestion was paused several times and the public replicas lagged "several days" (https://groups.google.com/g/crtsh/c/Frhhcg5qgMs). In 2024 "usually within 24 hours" was expected (https://community.letsencrypt.org/t/how-long-for-le-certs-to-show-up-on-crt-sh/211089). Incremental querying by `certificate.ID >` on the replica is the operator's own suggestion (same 2025 thread). | **Kept as today:** the cadence scan's per-root query (`limes/intel/crtsh.py`, `exclude=expired`). Not a near-real-time source: its ingest lag is hours to days, so polling it faster buys nothing **(inference)**. |
| **Cert Spotter API** (hosted) | `GET https://api.certspotter.com/v1/issuances?domain=…&include_subdomains=true&match_wildcards=true&after=<id>`. Pagination uses `after`. An empty page carries `Retry-After`, and a throttled call returns `rate_limited`. Unauthenticated use is limited and "personal or evaluation" only (https://sslmate.com/help/reference/ct_search_api_v1). The free plan allows 100 single-hostname and **10 full-domain** queries per hour; the firehose costs $1,000/month (https://sslmate.com/ct_search_api/). | **Chosen as fallback** when a key is configured. It also cross-checks the watcher (below). |

### Decision

- **Primary (opt-in): a self-hosted certspotter.** It runs in a new `ct-watch` compose service (profile `realtime`, setting `LIMES_CT_WATCH=true`), supervised by a Limes management command.
  - Only watchlist matches ever leave certspotter, so privacy holds by construction: non-matching certificates are never seen by Limes, let alone stored.
  - Persisted per-log positions mean a restart, including the watchlist-change restart, loses nothing.
- **Fallback 1 (opt-in, key): a Cert Spotter API poller** for owned roots. It is budgeted to 7 of the 10 free full-domain queries per hour.
- **Fallback 2 (always on): cadence.** This is the existing per-root `asm` scans, whose passive intel queries crt.sh.
- **When the watch is off, the card says "cadence only". When it is on but unhealthy, the card says "degraded" and an alert is sent once.** Limes degrades to cadence, never to silence.

### Running certspotter

- **Process.** `python manage.py ct_watch` runs in the `ct-watch` container (image `limes:local`). It writes the watchlist from the database and starts `certspotter -watchlist <file> -state_dir /var/lib/ct-watch/state -script <hook> -no_save -start_at_end -healthcheck 1h` as a subprocess. The arguments are a list and no shell is used.
  - It is restarted with SIGTERM when the watchlist hash changes, at most once per `LIMES_CT_WATCH_RESTART_MIN` (300 s).
  - Positions persist, so certificates logged during the restart are still read.
  - `-start_at_end` only affects logs certspotter has never seen. It stops a first start from walking history, which is days of download (man page).
- **Binary.** certspotter is built in a multi-stage Docker build: `go install software.sslmate.com/src/certspotter/cmd/certspotter@v0.25.0` in a pinned `golang` stage, then the binary is copied into the image. It is pinned, never `@latest`.
- **Hook** (`limes/ct/hook.py`). It is stdlib only, runs with `python3 -I`, and always exits 0.
  - On `discovered_cert` it reads `JSON_FILENAME` (refused above 256 KB), keeps `dns_names` (at most 1,000), and adds `TBS_SHA256`, `CERT_SHA256`, `ISSUER_DN` (truncated to 500 chars), `NOT_BEFORE_RFC3339`, `NOT_AFTER_RFC3339`, `LOG_URI` and `ENTRY_INDEX`.
  - It writes `spool/<tbs_sha256>.json` with tmp-then-rename. The name must be 64 hex characters, otherwise the entry is dropped.
  - On `error` / `malformed_cert` it writes `spool/_health/<unix>.json` with `SUMMARY` capped at 2 KB.
  - The temp files certspotter passes are deleted after the hook returns, under `-no_save` (certspotter-script man page). That is why the hook copies.
- **Ingest loop** (inside `ct_watch`, every 5 s). It reads spool files and treats them as untrusted (size cap, JSON schema check).
  - Each file is matched and stored in one transaction, then deleted.
  - At most `LIMES_CT_INGEST_PER_MIN` (600) files are ingested per minute. The rest wait in the spool, which is bounded by disk. **(inference)** It stays tiny, because only matches are written.
  - Then it calls `deliver_immediate` for each touched project.
  - It calls `close_old_connections()` between loops. pgbouncer runs transaction pooling, so the loop holds no session state, takes no advisory locks and keeps no long transactions.
- **Heartbeat.** Every loop writes Redis `limes:ct:watch` = `{pid_alive, started_at, restarts_10m, watchlist_size, watchlist_hash, last_ingest_at, last_match_at, spool_depth, health: ok|error, last_error_at, last_error_summary}`, with a 10-minute TTL. The service's Docker healthcheck reads it.
- **Egress.** certspotter needs HTTPS to the log hosts and the log lists, which is about 80 hosts (counted above), so an allowlist is impractical **(inference)**. `HTTPS_PROXY` is honoured (man page) for operators who route egress.

### Watchlist

The watchlist is the union across projects, deduplicated:

| Entry | Covers | Source |
|---|---|---|
| `.root` | the root and its whole subtree | every `root_domain` with `scope_tier='owned_root'` and cadence not `off`. It must pass `registrable(value) == value`, so a public suffix is never watched |
| `host` (exact) | one name | owned `hostname` assets not under any owned root, such as a manually added `app.vendor-hosted.com` |
| `.lookalike` | a lookalike's subtree | if project 3 ships lookalike candidates (its spec, `2026-10-23-discovery-reputation-design.md`, was not yet written when this was drafted, so this is not a dependency): candidate roots it marks as lookalikes, still `candidate` and not rejected |

The total is capped at `LIMES_CT_WATCHLIST_MAX` (5,000). `NOTE:` over the cap, owned entries win, lookalikes are dropped first, and the card says how many. The upgrade path is a measured cap once certspotter's per-entry cost is known.

### Match logic (`limes/ct/match.py`, pure functions)

Limes re-matches every name itself and never trusts which watch item fired.

1. **Normalise each name:**
   - strip and lowercase it, and drop a trailing dot;
   - a leading `*.` sets `wildcard=True` and is removed;
   - reject anything that fails `validators.domain`, is longer than 253 characters, or contains anything but `[a-z0-9.-]` after IDNA encoding;
   - reuse `intel.crtsh._clean` and extend it.

   IP SANs are ignored, since the watch is DNS-only.
2. **For each project, classify each name:**
   - **owned:** the longest owned root that is equal to it or a dot-suffix of it;
   - **owned host:** an exact owned hostname;
   - **lookalike:** under a watched lookalike;
   - **other.**
3. **Owned, non-wildcard, not yet an asset:** `inventory.upsert_hostname_asset(project, name, parent=root, source='ct', evidence='cert:<tbs[:16]>')`. A new label `'ct': 'CT'` goes into `monitor.FOUND_BY`. The asset is enqueued for an immediate check.
4. **Owned and wildcard:** no asset is created, because there is nothing to enumerate. The sighting is attached to the root.
5. **Owned and existing:** the asset is enqueued so TLS is re-checked. The per-asset cooldown applies.
6. **Lookalike:** evidence on the candidate (`record_fact(cand, 'cert', tbs)`). It is never contacted.
7. **Other names on the same certificate:** the co-tenant rule `run_crtsh` already applies. A certificate listing more than `SHARED_CERT_LIMIT` (20) registrable domains is not ownership evidence. Otherwise each registrable domain becomes a `candidate` through `upsert_candidate`, capped at `MAX_CANDIDATES_PER_ROOT` per hour. That logic is factored out of `run_crtsh` into a shared function used by both. Nothing else about non-matching names is stored.
8. **Dedupe:** `CertSighting` is unique on `(project, tbs_sha256)`. certspotter itself dedupes precertificate and certificate pairs (v0.24). The same certificate in a second log, a fallback poll or a re-delivery is a no-op.

### Hostile data (certificate fields are attacker-controlled)

- **Names are validated before any use, as above.** A name is only ever:
  - stored when it matched;
  - resolved and contacted only when it lands under an owned root, and then only through `monitor.check_asset`, i.e. `safe_fetch` with vetted, pinned, non-reserved IPs.
- **Lookalike and co-tenant names are never contacted.** Limes never fetches URLs from certificate fields (AIA, CRL, OCSP).
- **DNs and names are stored truncated, rendered through Django autoescape, inserted by JS with `textContent` only, and logged with `%r`** so they can't inject into logs. A certificate with more than 1,000 SANs is processed for the first 1,000, and the card counts it as `truncated`.
- **Spool files are parsed with a size cap and a schema.** Filenames come only from the validated hex hash.

### Privacy

- certspotter emits only matches. Limes stores only names that matched plus a count of the others (`other_names`).
- Co-tenant registrable domains reach the inventory only through the existing candidate rule. The world's issuance stream is never stored.
- The Cert Spotter API is asked only about owned roots. Its key is read from the environment and never logged; requests log only the root and the status.

### Fallback 1: Cert Spotter API poller (`limes/ct/api.py`)

- **Task.** It is a beat task, `poll_ct_api`, every 60 s, on the IO queue, under `tick_lock('poll_ct_api')`. It is active only when `LIMES_CERTSPOTTER_API_KEY` is set.
- **Rate.** The provider gets `http.MIN_INTERVAL['certspotter'] = 3600 / LIMES_CERTSPOTTER_HOURLY_BUDGET` (7, which is about 514 s). That is one root's page per slot, oldest polled first.
- **Cursor.** Each root keeps its cursor in `enrichment['certspotter'] = {after, polled_at}`. A page with `Retry-After` pushes that root's next poll back.
- **Baseline.** A root's first poll is silent, like a first sweep. **(inference)** With no `after`, the API starts from the oldest issuance, so a large root's baseline may take several slots. The builder should check whether a recent `id` can seed `after`.
- **Results** go through the same `match` / `ingest` code with `source='certspotter_api'`.
- **Cross-check.** A certificate found by the API with no watcher sighting for over 1 h, while the watcher reports healthy, counts as `api_only` on the card. That is direct evidence the watcher missed something.

## Event-driven checks: the event queue

### Design

The queue is a Redis sorted set, `limes:evq`, and the existing `monitor_assets` tick drains it. It reuses the monitor's lock, budget, `_ours` re-read and `safe_fetch`, so no new worker, beat entry or concurrency domain is needed.

- **`event_queue.enqueue(asset, reason)`** does the following:
  - It returns early when `LIMES_EVENT_CHECKS` is off, or the asset isn't owned or monitored (the same test as `monitor._ours`).
  - **Cooldown:** `SET limes:evq:cool:<asset_id> 1 NX EX LIMES_EVENT_COOLDOWN` (900 s). If the key already exists, the request is dropped and counted as `cooled`.
  - **Bound:** when `ZCARD >= LIMES_EVENT_QUEUE_MAX` (1,000), the request is dropped and counted as `overflow`. The asset is not lost: a never-checked asset already sorts first in `due_assets`, so the cadence picks it up.
  - **Idempotency:** `ZADD limes:evq NX <enqueued_unix> <asset_id>`. Enqueuing the same asset twice gives one entry. The reason goes into `HSET limes:evq:why <asset_id> <reason>`, with a bounded set of reason codes and never a name.
  - On a Redis error it logs the error type only and returns. A request lost that way falls back to cadence.
- **Draining** happens at the start of `monitor._tick`:
  - `ZPOPMIN` up to `ceil(MAX_PER_TICK * LIMES_EVENT_SHARE)` items (10 with the defaults), within `TICK_BUDGET * LIMES_EVENT_SHARE` seconds (25 s).
  - Each item is re-read through `_ours`. Hostnames under a root whose scan is in progress are dropped as `covered`, because the scan covers them.
  - Each item runs `check_asset(asset)`. The remaining budget then goes to cadence-due assets as today, so **cadence is never starved**.
  - Items not reached in the budget are re-added with their original score, so they keep their place.
- **Concurrency.** One drainer runs at a time, because `monitor_assets` already holds `tick_lock` (Redis, owner token and TTL, never a Postgres advisory lock behind pgbouncer). The drainer and the cadence share one loop, so the same asset is never checked twice at once.
  - Event checks run on the **IO queue**, through the existing `monitor_assets` routing.
  - The 60 s tick sets the T2 floor. The next bullet adds 15 s ticks while the queue is non-empty.
- **Faster ticks only when there is work.** A second beat entry, `drain-events`, runs every 15 s with `expires: 14`. It calls the same task with `events_only=True`.
  - It returns at once when `ZCARD == 0` or when the shared tick lock is held.
  - **(inference)** This keeps T2 at about 1 minute when the queue is short and costs one Redis call per 15 s when idle.
- **Re-check for precertificates.** When a CT-triggered check of a new hostname finds it `unresolved`, it is re-enqueued with reason `ct_recheck`. This happens at most twice: after 1 h and after 24 h. A delayed member is stored with a future score, and the drainer pops only scores ≤ now.
- **A check's `asset_new` event fires after the check** (that event is the change event, not the queue item), so its `ports` are known, and the existing rule decides immediacy: immediate when a `net.exposed_*` service is exposed. A CT-triggered check is never a silent baseline for the asset itself, because the asset is new by definition. Its children (newly found IPs) follow the existing first-check-silent rule.

### Triggers

| Trigger | Where | Enqueues |
|---|---|---|
| New owned hostname from CT | `ct/ingest.py` | the hostname (`ct_new`) |
| New certificate on an existing owned hostname | `ct/ingest.py` | the hostname (`ct_cert`), subject to the cooldown |
| `asset_new` from a range sweep, the monitor or passive intel | `events.record_asset_new` gains an enqueue call | the new asset (`asset_new`) |
| Manual add or Confirm of a hostname or IP | the AddAssets and Confirm paths, after commit | the asset (`manual`). Roots already get an immediate scan via `ensure_scan_target` |
| Newly exposed risky service (`issue_new` with `net.exposed_*` on an IP) | `alerts/issues.sync_issues` | hostnames linked to that IP, at most 20 (`exposed`), so web and TLS are checked right away |
| DNS change on a crown jewel | the DNS watch (below) | the asset (`dns_change`) |

Every trigger goes through `enqueue`, so budgets, cooldown and caps apply uniformly. A burst cap protects the queue: after `LIMES_EVENT_BURST` (200) enqueues per project per hour, further requests for that project are counted as `burst` and left to the cadence.

### DNS change detection

- **Delta.** `inventory.record_resolution` already replaces a host's links. Before replacing them, it compares the new `{a, aaaa, cname}` with `enrichment['dns']` (the previous answer, stored now) and writes the new one.
- **A significant change** is any of these:
  - the CNAME target changed;
  - the name went from resolving to not resolving, or the reverse;
  - no new IPv4 address shares a /24 with an old one, and no new IPv6 address shares a /48.

  `NOTE:` that is a heuristic to keep CDN rotation quiet. The upgrade path is comparing ASNs from RIPEstat enrichment.
- **Event.** A significant change records `dns_changed`, which is digest-only, with `detail={'before': …, 'after': …}` holding addresses and names only. It is not immediate, because takeover detection doesn't exist yet. When takeover checks arrive, a CNAME to an unclaimed service becomes the immediate case.
- **DNS watch.** Inside `monitor._tick`, after the event drain, assets with `cadence_tier='crown_jewel'` (hostnames and roots) are re-resolved with **DNS only** (A, AAAA, CNAME through `collect._resolve`), with no contact to the target:
  - every `LIMES_DNS_WATCH_INTERVAL` (900 s);
  - at most `LIMES_DNS_WATCH_PER_TICK` (30) per tick;
  - stamped in `enrichment['dns']['watched_at']`.

  A significant delta enqueues a full light check. Every other monitored asset gets delta detection at its normal monitor interval.

## Surfacing

### Live-ish Overview: polling, not SSE

- **Why not SSE.** gunicorn runs `gthread` with `WEB_WORKERS = max(2, min(9, 2*cpus+1))` workers × 4 threads (`web/entrypoint.sh`, `limes/sizing.py`), so a 2-CPU box has 20 request threads.
  - **(inference)** SSE would pin one thread per open tab: a handful of dashboards left open would starve the app.
  - nginx buffers proxied responses by default (`proxy_buffering on`, http://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_buffering), and `proxy_read_timeout 300` (`config/nginx/limes.conf`) would cut idle streams. Both would need special-casing.
- **Polling instead.** A new endpoint, `GET /<slug>/dashboard/live?since=<event_id>`, returns:
  - events with `id > since`, limited to 20, as `{id, kind, label, title, severity, asset, created_at}`;
  - the Real-time card payload (below).

  It is login-required, uses the same permission and project scoping as the dashboard `index`, and validates `since` as an int. It does a couple of indexed queries plus Redis reads, and doesn't touch `project_stats`.
- **Client side.** `overview.js` polls every `LIMES_LIVE_POLL_SECONDS` (30), only while `document.visibilityState === 'visible'`, with back-off to 5 minutes after errors.
  - It prepends new rows to "Recent changes" with `textContent` and bumps the "What changed" counts by marking the card stale ("Updated — refresh").
  - The feed list gets `aria-live="polite"`, and animations respect `prefers-reduced-motion`.
- **Cost.** **(inference)** About 2 requests a minute per open tab, which is negligible next to the 60 s stats cache.

### The Real-time card (it extends the Overview's "Monitoring" card)

The card shows:
- **Mode:** `real-time` (watch on), `API polling` (key only), or `cadence only`.
- **State:** `healthy` / `degraded` (with the reason) / `off`.
- **Certificate watch:**
  - heartbeat age;
  - last match age, labelled "last certificate for your names". It is not a health signal: a quiet estate can go weeks without a certificate;
  - watchlist size and how many entries were dropped by the cap;
  - restarts in the last 10 minutes;
  - spool depth;
  - the last certspotter error summary, escaped;
  - `api_only` misses in the last 7 days.
- **Event queue:** depth, oldest-item age, and the 24 h counters `checked`, `cooled`, `overflow`, `burst`, `covered`.
- **Latency:** p50/p95 of T2 (enqueue → checked) and T3 (event → notified) over 24 h, from the stored stamps.
- **DNS watch:** crown jewels watched, and the oldest watch age.
- **Cert Spotter API** when configured: queries this hour against the budget, and the oldest root poll age.

**Degraded** means the watch is on and any of these holds:
- the heartbeat is missing or older than `LIMES_CT_WATCH_STALE` (180 s);
- more than 3 restarts in 10 minutes;
- certspotter reported an `error` in the last hour;
- spool depth is above 1,000.

On a transition into degraded, Limes records a `monitoring_degraded` event, which is immediate (a severity-3-equivalent `ALWAYS_IMMEDIATE`). It is sent once per transition, and `monitoring_restored` goes to the digest. The event is project-less, so it fans out to every project. The builder picks: fan-out rows, or a nullable project.

## Goals

- An opt-in certificate watch (certspotter) that meets T1, with only matches stored, plus an opt-in API fallback and an always-on cadence fallback.
- A bounded, idempotent event queue that meets T2 for new or changed owned assets, through `monitor.check_asset` and `safe_fetch`.
- DNS-change detection: deltas everywhere, and a 15-minute watch for crown jewels (T4).
- New `ChangeEvent` kinds:
  - `cert_new`: digest by default. Immediate when the certificate's issuer (organisation from the issuer DN) has not been seen for that root in 365 days, after the root's baseline. This is the classic CT mis-issuance signal;
  - `dns_changed`;
  - `monitoring_degraded` and `monitoring_restored`.

  All are in `CHANGE_LABELS` and the digest.
- Polling live updates on the Overview and the Real-time card.

## Non-goals

- Active port or range scanning for faster exposure detection (T5 stays at 24 h).
- Keyword or fuzzy lookalike matching across the whole stream (needs certstream-server-go; that is the upgrade path).
- Takeover detection.
- Websockets or SSE.
- A hosted or paid feed (Cert Spotter firehose).
- Backfilling CT history. The cadence crt.sh query already does that per root.

## Anti-goals

- **No alert storms.**
  - `cert_new` coalesces: at most one event per `(project, root)` per `LIMES_CT_EVENT_WINDOW` (1 h). Later sightings in the window update that row's `detail.count` and a sample of at most 20 names, and add no rows.
  - The existing 10-per-project-per-hour immediate cap and the digest still apply.
  - `asset_new` from CT is immediate only when the check finds a risky exposed service.
- **No unbounded queues.**
  - The event queue is capped (1,000), with per-project bursts (200 per hour) and per-asset cooldowns (15 min).
  - Spool ingestion is rate-capped.
  - The watchlist is capped.
  - Every drop is counted and shown, and the dropped work falls back to cadence.
- **No contact with non-owned hosts beyond DNS.** Only owned assets, through `safe_fetch`. Lookalikes, co-tenants and candidates are never contacted by this project.
- **No storage of non-matching certificates.** Not even counts per foreign domain; only `other_names` per sighting.
- **No secrets in logs.** The Cert Spotter key comes from the environment. The `Authorization` header is never logged, and errors log the type only, as `deliver._webhook` does.
- **Hostile names are always escaped.** Autoescape, `textContent` and `%r` in logs.
- **No Postgres advisory locks** (pgbouncer transaction pooling). All locks are Redis `tick_lock` or `SET NX`.
- **Never silent.** A watch that is enabled but not working is visible on the card and is alerted once.

## Constraints

- Django 3.2, Celery 5.4, gevent IO workers, Redis 7.2 with `noeviction` and AOF, so queue keys aren't evicted but must stay bounded.
- PostgreSQL behind pgbouncer in transaction pooling.
- Beat entries use `expires` just under their period. `TASK_PLAN` stays the single source of queues and limits:
  - `poll_ct_api` uses `(IO, 15 * MIN)`;
  - `monitor_assets` already uses `(IO, 15 * MIN)`.
- `ct_watch` is a long-running process, not a Celery task. It never runs on scan workers.

## Data model

- **`CertSighting`**:
  - `project` FK;
  - `asset` FK, nullable, `SET_NULL`: the matched hostname, or the root for wildcard and root names;
  - `tbs_sha256` char(64);
  - `cert_sha256` char(64), nullable;
  - `names` JSON (matched names only, at most 100);
  - `other_names` int;
  - `wildcard` bool;
  - `issuer` char(500);
  - `not_before`, `not_after`;
  - `log_uri` char(500);
  - `entry_index` bigint, nullable;
  - `source`: `certspotter`, `certspotter_api` or `crtsh`;
  - `first_seen_at`.

  It is unique on `(project, tbs_sha256)` and indexed on `(project, first_seen_at)`. Retention: rows older than 400 days are deleted by `age_assets` (the 365-day issuer history plus margin).
- **`ChangeEvent.kind`** gains `cert_new`, `dns_changed`, `monitoring_degraded` and `monitoring_restored`. The field is a free CharField, so no migration is needed. The `events.KINDS` and `is_immediate` rules are updated.
- **`Asset.enrichment` keys:**
  - `dns`: `{a, aaaa, cname, changed_at, watched_at}`;
  - `certspotter`: `{after, polled_at}` on roots;
  - `monitor.enqueued_reason` for the card.

  No new columns.
- **Redis** (all bounded or TTL'd):
  - `limes:evq` (zset) and `limes:evq:why` (hash), both cleaned on pop;
  - `limes:evq:cool:<id>` (TTL);
  - `limes:evq:stats:<yyyymmdd>` (hash, 2-day TTL);
  - `limes:ct:watch` (heartbeat, 10-minute TTL);
  - `limes:ct:lat:<yyyymmdd>` (capped list for the p50/p95, 2-day TTL).
- **Volume** `ct_state` for the certspotter state dir and the spool.

## Settings (environment, with defaults)

| Name | Default | Note |
|---|---|---|
| `LIMES_CT_WATCH` | `false` | Opt-in. It contacts every CT log continuously, at **(inference)** about 157 GB/day inbound. Turn it on together with `make up REALTIME=1` (adds `--profile realtime`, like `LLM=1`) |
| `LIMES_CT_WATCH_STALE` | `180` s | Heartbeat age that means degraded |
| `LIMES_CT_WATCH_RESTART_MIN` | `300` s | Minimum gap between watchlist restarts |
| `LIMES_CT_WATCHLIST_MAX` | `5000` | |
| `LIMES_CT_INGEST_PER_MIN` | `600` | |
| `LIMES_CT_EVENT_WINDOW` | `3600` s | `cert_new` coalescing |
| `LIMES_CERTSPOTTER_API_KEY` | empty | Opt-in fallback. Never logged |
| `LIMES_CERTSPOTTER_HOURLY_BUDGET` | `7` | Of the free plan's 10 full-domain queries per hour |
| `LIMES_EVENT_CHECKS` | `true` | Local only: it reorders checks of owned assets, with no new third party |
| `LIMES_EVENT_QUEUE_MAX` | `1000` | |
| `LIMES_EVENT_COOLDOWN` | `900` s | |
| `LIMES_EVENT_BURST` | `200` per project per hour | |
| `LIMES_EVENT_SHARE` | `0.5` | The share of a monitor tick events may use |
| `LIMES_DNS_WATCH_INTERVAL` | `900` s | Crown jewels only. `0` turns it off |
| `LIMES_DNS_WATCH_PER_TICK` | `30` | |
| `LIMES_LIVE_POLL_SECONDS` | `30` | `0` turns live polling off |

All of these respect `LIMES_CONTINUOUS_SCANS=false` as the master kill switch.

## Module layout

- `web/limes/ct/`: `match.py` (pure), `ingest.py`, `watch.py` (supervisor, watchlist, spool loop, heartbeat), `hook.py` (stdlib only), `api.py` (Cert Spotter poller), `health.py` (card payload and degraded rule).
- `web/limes/event_queue.py`.
- Small edits to:
  - `monitor.py`: drain, DNS watch, `FOUND_BY`;
  - `tasks/inventory.py`: DNS delta;
  - `alerts/events.py`: new kinds;
  - `alerts/issues.py`: the exposure trigger;
  - `tasks/intel.py`: the co-tenant helper factored out;
  - `celery_routing.py` and `settings.py`;
  - `dashboard/`: the live view, the card and `overview.js`;
  - `docker-compose.yml` and `Makefile`: a `ct-watch` service under profile `realtime`, with a `REALTIME=1` switch like `LLM=1`, with the `ct_state` volume, `mem_limit` 512m, no published ports, and a healthcheck on the heartbeat;
  - `web/Dockerfile`: the certspotter build stage.

## Testing (what can actually break)

- **`match.py`:**
  - wildcard handling;
  - longest-root wins;
  - a public-suffix root is refused;
  - IDNA and junk names are rejected;
  - a name equal to a root is matched;
  - lookalike against owned;
  - more than 20 registrable domains means no candidates.
- **Ingest:**
  - duplicate `tbs` is a no-op;
  - wildcard creates no asset;
  - a new hostname is upserted and enqueued;
  - `cert_new` coalesces within the window;
  - a new-issuer certificate is immediate;
  - a hostile DN is truncated;
  - an oversized or invalid spool file is dropped.
- **Hook:** writes atomically, refuses a non-hex `TBS_SHA256`, exits 0 on garbage.
- **Event queue:**
  - idempotent double enqueue;
  - cooldown;
  - overflow and burst are counted;
  - an unreached item keeps its score;
  - a delayed re-check isn't popped early;
  - a stopped or rejected asset is skipped;
  - cadence still gets half the tick.
- **DNS delta:** CDN rotation within a /24 stays silent; a CNAME change and resolve↔NX each emit one event.
- **Degraded rule:** stale heartbeat, the restart storm, and recovery each emit once.
- **Live endpoint:** project scoping, `since` validation, escaping.
- **Real flow:** run `--profile realtime` against the live logs, add a test root the operator controls, issue a certificate (for example with a staging ACME client), and watch the card and feed.

## Operator docs (outline, for `docs/`)

1. What "real time" means in Limes: the targets table, and what isn't real time.
2. Turning it on: `LIMES_CT_WATCH=true` and `make up REALTIME=1`, bandwidth expectations, and an `HTTPS_PROXY` note.
3. Optional Cert Spotter API key: how to get one, and the free-plan limits.
4. Reading the Real-time card and the degraded reasons, and what to do (check egress, the certspotter errors shown, restarts).
5. Tuning the queue, cooldown and DNS watch.
6. Privacy statement: only matches are stored; what is sent to whom.

## Left to the builder

- The exact Go build stage, and whether `software.sslmate.com/src/certspotter/cmd/certspotter` is the right module path for v0.25.0.
- Whether certspotter runs hooks concurrently. The spool design is safe either way.
- Measuring certspotter's real bandwidth, CPU and RAM with `--profile realtime` for 24 h, and putting the numbers in the operator docs to replace the inferred figure.
- Seeding the Cert Spotter `after` cursor, if possible.
- Card layout and wording, and how the "N new" refresh affordance looks.
- Fan-out rows or a nullable project for `monitoring_degraded`.

## Decisions for the user (my recommended default in bold)

1. **Should the certificate watch be on by default?** **No, opt-in:** it pulls about 157 GB/day of inbound traffic **(inference)** and contacts every CT log continuously.
2. **Should a free Cert Spotter API key be used as the fallback?** **Yes, if you add one.** It's off without a key. Check SSLMate's terms fit your use: unauthenticated use is "personal or evaluation" only.
3. **Should `cert_new` be immediate when a root gets a certificate from a CA not seen for it in 365 days?** **Yes.** Everything else stays digest-only.
