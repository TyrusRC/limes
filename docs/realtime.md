# Near-real-time monitoring

Limes can watch certificate transparency (CT) logs as certificates are published, check new owned assets within
minutes, and notice DNS changes on crown-jewel names. Event-driven checks and the live Overview are on by default;
the certificate watch is opt-in. The container and security details are in [realtime-ct-watch.md](realtime-ct-watch.md).

## 1. What "real time" means

| | Event | Target | Holds when |
|---|---|---|---|
| T1 | A new certificate naming an owned root, owned hostname or watched lookalike is published; Limes records a sighting and its change event | 15 min p95 from the log publishing the entry | The certificate watch is on and healthy |
| T2 | A new owned subdomain from any source gets its first light check (resolve, InternetDB, TLS, web, exposure) | 5 min p95 from discovery | The event queue is under its cap |
| T3 | An immediate alert reaches in-app, chat and webhook | 60 s p95 from the event row being written | The hourly cap (10 per project) is not spent |
| T4 | A DNS change (A/AAAA/CNAME) on a crown-jewel hostname | 15 min | Always (DNS only) |
| T6 | A new certificate seen without the watch | The cadence scan interval (24 h crown jewel, 7 d standard) plus crt.sh's ingest lag; with an API key, about `ceil(roots / 7)` hours per root | The watch is off or degraded |

Not real time: DNS changes on other assets (the monitor interval: 24 h active, 30 d inactive), and newly exposed
services on an owned IP (at most the 24 h active interval, plus InternetDB's own data age). Limes does no active
port or range scanning to speed this up. The upstream leg of T1, from the log to certspotter, is not measured per
certificate; the card shows certspotter's own "not falling behind" health instead. Everything here stops with
`LIMES_CONTINUOUS_SCANS=false`.

## 2. Turning the certificate watch on

1. Set `LIMES_CT_WATCH=true` in `.env`.
2. Start with `make up REALTIME=1` (adds the `realtime` compose profile and the `ct-watch` service).

**Bandwidth: about 157 GB/day inbound. This is inferred from the size of the CT log ecosystem, not measured.** The
watcher contacts every CT log continuously. Check that your link, any data cap and your policy allow it before
enabling. The 24 h measurement that replaces this figure, and an end-to-end test certificate, contact the live CT
ecosystem and need the owner's explicit go-ahead. The build and the tests do not perform either; the procedure is in
[realtime-ct-watch.md](realtime-ct-watch.md#operator-procedure-not-run-by-the-build-or-the-tests).

- Egress goes through `HTTPS_PROXY` when it is set.
- The `ct_state` volume (mounted at `LIMES_CT_STATE_DIR`, default `/var/lib/ct-watch`) holds certspotter's log
  positions, the spool, the watchlist and `last.json`. A restart resumes from the saved positions; deleting the
  volume starts again from the logs' current ends, so certificates published meanwhile are not seen by the watch.
- The watcher idles (state `idle`) while there is nothing to watch, that is, no owned root. It is not a fault.
- The watchlist holds owned roots, owned hosts and lookalikes, capped at `LIMES_CT_WATCHLIST_MAX` with owned names
  winning. A change restarts certspotter at most every `LIMES_CT_WATCH_RESTART_MIN` seconds.
- Keep `LIMES_SECRET_KEY` set in `.env` (the installer does this). The container's root filesystem is read-only, so
  without it Django would try to create its secret file under `/usr/src/app` and fail. Log files go to `/tmp`
  (`LIMES_LOG_DIR`, set by the compose service).
- The hook exits non-zero when it cannot write the spool, so certspotter retries that certificate.
- The compose service has no published ports, a read-only root filesystem and `mem_limit` 512m (`CT_WATCH_MEM`).
  The 512m figure is a guess until measured.

## 3. Optional Cert Spotter API key (fallback)

If the self-hosted watch is off or degraded, Limes can poll SSLMate's Cert Spotter API instead. Set
`LIMES_CERTSPOTTER_API_KEY` in `.env`; without it the fallback stays off. The key is read from the environment only
and is never logged.

- The free plan allows 100 single-hostname and 10 full-domain queries per hour; Limes uses 7
  (`LIMES_CERTSPOTTER_HOURLY_BUDGET`, 1 to 10), one per owned root slot, so more than 7 roots share the hour.
  https://sslmate.com/ct_search_api/
- SSLMate's API terms limit unauthenticated use to "personal or evaluation" use. Limes only calls it with a key, but
  check SSLMate's terms for your use of the free plan before adding one. https://sslmate.com/help/reference/ct_search_api_v1
- The first pass per project is a silent baseline: it pages through each root's history until an empty page. While a
  project is baselining, exactly this is silent: no `cert_new` event, no `asset_new` for the names it finds, no
  event-queue item or recheck chain for them, and no charge against `LIMES_CT_NEW_HOSTS_PER_HOUR`. Still done: the
  sighting is stored, new hostnames under an owned root are created as owned (from a separate allowance of 10 times
  `LIMES_CT_NEW_HOSTS_PER_HOUR` an hour), co-tenant candidates are suggested as usual, and the issuer history is
  learned. Names past the allowance become candidates, and a later sighting promotes one once allowance exists.
- While the watch is healthy, the API also cross-checks it: a certificate the API saw but the watch did not shows
  as "api-only" on the card.

## 4. Reading the Real-time card

The Overview card shows the mode (`real-time` with the watch, `api` with only a key, `cadence` otherwise), the state
(`off`, `idle`, `healthy`, `degraded`), the watch figures (heartbeat age, last match, watchlist size and entries
dropped, restarts in 10 min, spool depth, last error), the event queue (depth, oldest age, counts) and the T1 to T3
latencies over 24 h. The Overview refreshes itself every `LIMES_LIVE_POLL_SECONDS` while the tab is visible, backs
off on errors and says so when polling fails or the session ends.

A degraded watch records one `monitoring_degraded` alert per project (after `LIMES_CT_DEGRADED_GRACE_MIN` minutes if
it never came up) and one "restored" entry in the digest.

| Reason | Meaning | What to do |
|---|---|---|
| The watcher has not reported | No heartbeat in Redis | Is `ct-watch` running (`make up REALTIME=1`)? Check its logs and that it shares Redis with the app |
| The watcher stopped reporting | Heartbeat older than `LIMES_CT_WATCH_STALE` (default 180 s), unreadable, or from the future | Check the container is not stuck or OOM-killed (512m) and that the host clock is right |
| certspotter is not running | The child process is gone | Read the container logs; the supervisor restarts it, rate limited |
| certspotter keeps restarting | More than 3 restarts in 10 min | Read `last_error_summary`; usually egress, a proxy or a bad volume |
| certspotter reported an error | An error in the last window | Check egress to the CT logs and `HTTPS_PROXY` |
| Certificate backlog is growing | Spool depth over 1,000 files | Ingest is behind: look at `LIMES_CT_INGEST_PER_MIN`, the worker and the database |

## 5. Tuning

| Setting | Default | Effect |
|---|---|---|
| `LIMES_EVENT_CHECKS` | `true` | Event-driven checks reorder checks of owned assets; no new third party |
| `LIMES_EVENT_QUEUE_MAX` | `1000` | Queue cap; overflow is counted, not queued |
| `LIMES_EVENT_COOLDOWN` | `900` s | Minimum gap between event checks of one asset |
| `LIMES_EVENT_BURST` | `200` | Event checks per project per hour |
| `LIMES_EVENT_SHARE` | `0.5` | Share (0.1 to 0.9) of each monitor tick's budget the queue may use; cadence always keeps the rest |
| `LIMES_CT_EVENT_WINDOW` | `3600` s | One `cert_new` digest row coalesces over this window |
| `LIMES_CT_NEW_HOSTS_PER_HOUR` | `200` | Owned hostnames certificates may add per project per hour |
| `LIMES_DNS_WATCH_INTERVAL` | `900` s | Crown-jewel names are re-resolved (DNS only) this often; `0` turns it off |
| `LIMES_DNS_WATCH_PER_TICK` | `30` | Most names the DNS watch resolves per tick |
| `LIMES_LIVE_POLL_SECONDS` | `30` | Overview refresh; `0` turns it off |
| `LIMES_CT_INGEST_PER_MIN` | `600` | Spool files ingested per minute |
| `LIMES_CT_WATCH_STALE` | `180` s | Heartbeat age that makes the watch degraded and fails the container healthcheck |
| `LIMES_CT_DEGRADED_GRACE_MIN` | `15` | Minutes a watch that never came up waits before its one degraded alert |
| `LIMES_CT_WATCHLIST_MAX` | `5000` | Names on the watchlist; owned names win |
| `LIMES_CT_WATCH_RESTART_MIN` | `300` s | Minimum gap between watchlist-driven certspotter restarts |
| `LIMES_CT_STATE_DIR` | `/var/lib/ct-watch` | Where the watcher keeps state, spool and watchlist; match the `ct_state` mount |

The queue is drained by the `drain-events` beat tick every 15 s (alongside the 60 s `monitor-assets` tick). A drain
steps aside when the next full tick is due, so the cadence is not starved.

## 6. Privacy

Only matches are stored: a `CertSighting` for a certificate that names an owned or watched name. Certificates for
other names are discarded by the hook and never written to the database. Limes does not fetch AIA or OCSP URLs from
certificates.

- CT logs see that someone downloads their entries. They do not see what Limes watches; matching is local.
- SSLMate (Cert Spotter) sees your owned roots, and only when `LIMES_CERTSPOTTER_API_KEY` is set. Without a key
  nothing is sent to it.
- crt.sh, InternetDB and RIPEstat are used as before by scans; the event queue adds no new third party.

## Turning it off

Set `LIMES_CT_WATCH=false` (the supervisor idles and the card reads `off`) and stop the container:
`docker compose --profile realtime stop ct-watch`, or `make down REALTIME=1`. A plain `make down` does not include
the `realtime` profile and leaves `ct-watch` running. The `ct_state` volume is kept; remove it to start from the
logs' current ends.
