# Limes

Self-hosted external attack surface management for one organization. Limes keeps an inventory of
the domains, hosts, IPs, ranges and ASNs you own, discovers new ones continuously, scans them with a
fixed, quiet pipeline, turns what it finds into a risk score, and tells you when something changes.

Active testing only ever runs against assets confirmed as owned; everything else gets passive
checks. See [the roadmap](docs/superpowers/specs/2026-10-07-asm-platform-roadmap-design.md).

## What it does

| Area | What you get |
|---|---|
| **Inventory** | Every owned root domain, hostname, IP, CIDR range and ASN, with how it was found, when it was first and last seen, and its state (active, missing, stale, retired). Candidates found by passive sources wait in a review queue until you confirm or reject them. |
| **Discovery** | Certificate transparency, Shodan InternetDB, RIPEstat, DNS resolution and ownership scoring find new assets; auto-confirm needs a registry-verified delegation. Anything the tools miss you add by hand (domain, IP, range such as `203.0.113.0-203.0.113.255` or `203.0.113.0/24`, or `AS64500`) and it is tracked from then on. |
| **Continuous tracking** | Owned roots are rediscovered on a cadence (every 24 hours, 7 days or 30 days, or off). Hosts and IPs outside a scanned root are checked by a light monitor: daily when they have an open port, a live web answer or a mail record, monthly otherwise. |
| **Risk score** | A 0–950 score with an A–F grade (`limes-score-v3`): any critical finding caps the grade at C, any high at B. Waived issues are scored out of the headline and the raw score is shown beside it. |
| **Risk checks** | TLS certificates and protocols, HTTP security headers and cookies, SPF/DMARC, DNSSEC/CAA and exposed risky services, run against owned assets. |
| **Findings** | assay (DAST, runs nuclei) and mantis (SAST on the JavaScript, source maps and exposed `.git` the crawl collects). |
| **Change alerts** | New and returning issues, dropped scores, new assets and expired waivers go to in-app notifications, Slack, Discord, Telegram or Lark, and a signed webhook. High-signal changes alert immediately (at most 10 per project per hour); the rest arrive in one daily digest. |
| **Waivers and notes** | Accept a risk until a date (default 90 days, at most 365) or mark a false positive, with a reason and an audit trail; discuss issues in notes; see the score if chosen issues were fixed. |
| **Portal** | An Overview, an Issues page and an Assets page, in light and dark themes. |

The scan pipeline is fixed on purpose: amass + subfinder → dnsx → naabu → nmap → httpx → katana +
gau → assay → mantis. There is no per-tool plug-and-play; see [Scope and safety](#scope-and-safety).

## Install (Linux, Docker)

```bash
git clone https://github.com/TyrusRC/limes && cd limes
sudo ./install.sh          # -n for non-interactive
```

`install.sh` creates `.env` from `.env.example` with fresh random secrets and memory limits sized
to the host. Review it before continuing, and set `PGBOUNCER_TAG` to a tested
`edoburu/pgbouncer` tag. Compose refuses to start while it is empty.

Limes is then served at `https://<host>` (nginx on 443). Create the first admin user with
`make username`.

## Configuration

Settings are environment variables in `.env`. The ones you are most likely to touch:

| Variable | Default | What it does |
|---|---|---|
| `LIMES_CONTINUOUS_SCANS` | `true` | Rediscover owned roots on their cadence. `false` stops all automatic scans and monitoring. |
| `LIMES_ATTRIBUTION_AUTO_CONFIRM` | `true` | Auto-confirm candidates that pass ownership scoring and a registry-verified delegation. `false` only flags them. |
| `LIMES_ALERT_WEBHOOK_URL` / `LIMES_ALERT_WEBHOOK_SECRET` | empty | Signed JSON webhook for change alerts (HMAC-SHA256 in `X-Limes-Signature`); both must be set. HTTP is refused unless `LIMES_ALERT_WEBHOOK_ALLOW_HTTP=true`. |
| `LIMES_RANGE_ENUMERATION` | `false` | Expand owned ranges and ASNs into per-IP assets with reverse DNS and InternetDB lookups. See [Passive providers](#passive-providers). |
| `LIMES_RANGE_ADDRESS_CAP` | `4096` | Owned addresses allowed per project across ranges and ASNs (1 to 65536). |
| `LIMES_INTERNETDB_DAILY_BUDGET` / `LIMES_PTR_DAILY_BUDGET` | `5000` / `10000` | Daily lookup budgets for range enumeration, shared by all ranges. |

Chat channels (Slack, Discord, Telegram, Lark) are set up in the portal under Notification Settings.

## Common tasks

| Command | What it does |
|---|---|
| `make up` / `make down` | Build and start / stop the stack. `make up LLM=1` adds the optional local LLM. |
| `make username` | Create the first admin user |
| `make logs` | Tail service logs |
| `make test` | Run the core test suite in containers |
| `sudo ./update.sh` | Pull, rebuild and restart |

## Passive providers

Scans query three free, keyless sources; none of them contacts your targets:

| Provider | Used for |
|---|---|
| crt.sh | Hostnames under owned roots; other domains sharing your certificates become review candidates |
| Shodan InternetDB | Open ports, CPEs, vulnerability IDs and tags per IP; hostnames on owned IPs become candidates |
| RIPEstat | ASN, prefix and holder per IP; the announced IPv4 prefixes of an ASN you add |

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
- **Fixed toolset.** assay runs by absolute path with a minimal environment and a `PATH` that holds
  only approved tools (nuclei). Before every scan it lists what it can see and refuses to run if
  anything else is visible, because assay would use any of its supported external tools it finds
  (including exploitation tools such as sqlmap). To approve another tool, change
  `ASSAY_TOOL_ALLOWLIST` and the Dockerfile step together; read the notes in
  `web/limes/integrations/assay.py` first.
- **Untrusted data.** Finding names, hostnames, banners and logs come from the hosts you scan and are
  escaped everywhere they are shown, including in PDF reports.

## Upgrading

- The first scheduler ticks after an upgrade that links existing owned roots to scan targets scan
  every previously unlinked root, one per tick and at most two at a time, so expect a burst of scan
  activity.
- `manage.py reclassify_roots` converts old hostname rows that are really registrable roots (for
  example `example.co.uk`). It is idempotent and logs every change. Run it once after upgrading.
- Scheduled tasks `monitor_assets` and `enumerate_ranges` run on the `io` queue; the scheduler locks
  live in Redis.

## Status

Built and merged: inventory and discovery, continuous tracking of added assets, the risk score and
checks, change alerts, waivers, notes and the fix forecast, a native MCP server (Streamable HTTP and
stdio, personal API tokens; see [`docs/mcp.md`](docs/mcp.md)), and the portal in light and dark themes.
The Overview shows the score by category, exposure, certificates, technologies, remediation, discovery,
coverage, top risks and what changed.

## Security

Report vulnerabilities privately; see [.github/SECURITY.md](.github/SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
