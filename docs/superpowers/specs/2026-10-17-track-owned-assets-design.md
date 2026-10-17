# Track what you own: manual assets, IP ranges and ASNs under continuous monitoring

Status: approved by the user on 2026-10-17 ("ok approve"). Informed by UpGuard's docs (research notes: active = open port or MX; active assets rescanned daily, inactive monthly; ranges entered as start–end; manual adds kept private and removable).
- This is project 1 of 4 in the roadmap drawn from the UpGuard comparison. The others are a richer dashboard, more discovery sources, and near real-time.
- The user asked: "support case like asm miss asset and user add asset to manage and it will continue track".

Everything below is my call unless marked otherwise.

## Intent

When the scanner misses an asset, the user adds it, and from then on Limes must watch it the way it watches what it discovered itself. UpGuard's enterprise ASM makes the same promise for ranges: give it an IP range, and every newly connected host in that range is enrolled into monitoring automatically ("IP range monitoring regions", upguard.com/blog/enterprise-attack-surface-management). Its ASM guide sets the bar at risks and ratings updated "daily and on an ad hoc basis".

Today a manual add is mostly a label:
- An added root domain gets no scan target (`Domain`), so the continuous dispatcher skips it.
- Added hostnames and IPs are only checked if a scan of an owned root happens to cover them.
- A CIDR is declared owned but never enumerated.
- ASNs cannot be entered at all.
- `example.co.uk` is classed as a hostname, because of a two-label heuristic.

## Goals

- **Every manually added or confirmed asset is monitored on its cadence.** The cadence tiers are the existing ones: 24h, 7d by default, 30d, or off.
  - **Root domains:** `ensure_scan_target(asset)` creates or links the project's `Domain`, so the existing continuous dispatcher picks the root up. It is called from manual add, Confirm in the review queue, and auto-confirm (every path that makes an owned root). The first scan is due immediately; never-scanned roots already sort first.
  - **Hostnames and IPs outside any owned root's scan:** a new light monitor (below).
  - **CIDR ranges and ASNs:** enumerated and kept current (below).
- **Root classification uses the public suffix list.** `registrable(value) == value` means a root domain, otherwise it's a hostname. This replaces the two-label heuristic (`example.co.uk` is a root; `www.example.com` is a hostname).
- **IP ranges as start–end.** `1.2.3.0-1.2.3.255` is accepted too, converted to the covering CIDRs (`ipaddress.summarize_address_range`). UpGuard takes ranges this way.
- **ASN entry.** `AS12345` or `12345` with the AS prefix is accepted in Add assets.
  - Its announced prefixes come from RIPEstat (`announced-prefixes`), which Limes already uses for enrichment.
  - Each prefix is stored as a `cidr` asset whose parent is the ASN asset, with `sources: ['asn:AS12345']`.
  - The prefix list is refreshed on the ASN's cadence. Prefixes that appear become new CIDR children; prefixes withdrawn for 3 refreshes go `missing`, using the existing lifecycle.
- **CIDR enrollment, passive and safe by default.**
  - Each owned range is enumerated in batches per IP:
    - reverse DNS (PTR);
    - Shodan InternetDB (open ports, hostnames, CPEs and vulns, free and keyless).
  - An IP with any open port, PTR name or InternetDB hostname becomes an `ip` asset under the range: parent = the CIDR asset, `sources: ['cidr:<range>']`, tier `owned_host`.
  - PTR and InternetDB hostnames inside an owned root become `hostname` assets, as today's passive intel does. Names outside owned roots become candidates for the review queue, never owned automatically.
  - A host that appears in a range after its first enumeration is a new asset.
    - It gets a new change event kind, `asset_new`, which is also used for new hostnames and IPs found by the light monitor.
    - The event is immediate when the asset exposes a risky service (`net.exposed_*` rules), and digest-only otherwise.
    - UpGuard has had new-domain/IP alerts since 2022.
  - No active port scanning of ranges in this project. That needs `active_authorized` and comes later.
- **Light monitor for hosts and IPs** (`monitor_assets`, a beat task).
  - **Cadence follows UpGuard's activity rule:**
    - An asset is active if it has an open port, a live HTTP answer, or an MX record.
    - Active assets are checked daily; inactive ones every 30 days.
    - A cadence set explicitly by the user (including off) wins.
  - For each owned `hostname` or `ip` that is due and not covered by a recent scan of its root:
  - resolve it (A/AAAA/CNAME);
  - refresh InternetDB for its IPs;
  - run the existing risk checks on it (TLS, headers, email/DNS where applicable, exposed services);
  - record a sighting or a miss in the existing missing → stale → retired lifecycle;
  - sync tracked issues, so the score, Issues page and change alerts all include it.
- **The Assets page shows tracking.**
  - **Columns:** "Monitored" (cadence and next due), "Last checked", and "Found by" (manual, scan, CT, CIDR, ASN, attribution).
  - **Filters:** by source.
  - **Detail:** the asset modal shows the parent chain (ASN → range → IP).
  - **Stop:** "Stop monitoring" sets cadence off. Reject stays the removal path.

## Non-goals

- Active scanning (naabu/nmap) of IP ranges. That is a later project, gated on `active_authorized`.
- New discovery sources such as reverse WHOIS, typosquat or leaks. That's project 3.
- Dashboard changes beyond what existing widgets pick up automatically. That's project 2.
- Real-time CT streaming. That's project 4.
- Cloud-account connectors (AWS, GCP, Azure APIs).

## Anti-goals

- **A huge range or ASN flooding the system.**
  - Ranges larger than /20 (4,096 addresses) are refused, as are ASNs whose prefixes add up to more than 65,536 addresses. The message gives the reason and says what to add instead.
  - Enumeration is rate-limited to InternetDB's free limits. Batches spread over ticks; nothing hammers in one burst.
- **Anything inside an owned range that isn't owned getting promoted to owned.** Shared hosting and CDN ranges are the classic false positive, so names outside owned roots stay candidates.
- **Private or reserved space** being entered or enumerated. The existing `is_reserved_*` guards apply to ranges, prefixes from an ASN, and resolved IPs.
- **The light monitor touching an asset the user stopped or rejected,** or running twice at once for the same asset.
- **Losing what the user typed.** Every entry is either added, reported as existing, or reported with a reason it was refused.

## Design (my calls)

- **`ensure_scan_target(asset) -> Domain`** in `limes/`. It is idempotent and project-scoped, and creates the `Domain` the way the target views do. Called after commit in AddAssets, Confirm and auto-confirm, plus a one-off data migration that links existing owned roots that have no `Domain`.
- **ASN asset kind:** a new `ASSET_KINDS` entry `asn` (migration). The value is stored as `AS<number>`.
- **Due-ness for the light monitor and range refresh:**
  - Uses `Asset.last_resolved_at` (exists) and the asset's cadence tier.
  - Picked by a dispatcher like `dispatch_due_scans`, with an advisory lock, a per-tick budget, and the oldest due first.
  - Ranges and ASNs carry their enumeration cursor and last refresh in `enrichment`, so no new columns.
- **Rate limits:** one shared token bucket for InternetDB and RIPEstat calls per worker, stored in Redis. `NOTE:` names the ceiling (single-process accuracy) and the upgrade path.
- **Where it runs:** the existing `ORCHESTRATE` queue, with the beat entries next to `dispatch_due_scans`.

## Left to the builder

- Exact batch sizes per tick within the rate limits.
- Column layout on the Assets page.
- Message wording.
