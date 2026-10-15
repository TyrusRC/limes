# ASM module — Slice A5a: Delegation verification

Status: design approved in brainstorming 2026-10-15; awaits user review of this file before planning.
Parent: Limes ASM platform. Builds on A3c (attribution graph, auto-confirm shipped off), `main` at `b4b52d9`.
Spec basis: the A3c spec's "Amendment after final review" upgrade path: verify the delegation at the parent with a non-recursive NS query to the TLD servers, and require an authoritative SOA answer for the zone from our own nameservers. Only then re-enable auto-confirm by default.
Platform: Django 3.2 + Celery 5.4 + PostgreSQL, internal package `limes`.

## Module context

ASM slices: A0 ✓ · A1 ✓ · A2 ✓ · A3a ✓ · A3b ✓ · A3c ✓ · A4 risk scoring · **A5a this slice** · A5b continuous monitoring (cadence dispatcher, stale/retired states, change events and notifications).

A5 was split. A5a is small and closes the gap A3c left open. A5b schedules unattended scans, and those should auto-confirm only verified domains, so A5a goes first.

## Goal

Re-enable attribution auto-confirm by default, only for candidates whose ownership is proven at the registry. This needs two checks:

- The parent zone delegates the candidate to nameservers under our owned roots.
- Those nameservers answer authoritatively for the candidate's zone.

## Problem (from A3c)

`collect_dns` reads NS records through a recursive resolver. That returns the child zone's own NS RRset, which the domain's owner writes. An outsider can list our nameservers in their zone while the registry delegates the zone to their own servers. The zone still resolves, so A3c's "working delegation" check passes. Auto-confirm would then turn their domain into an owned root and aim our scanner at whatever their A records point to.

## Decisions taken in brainstorming

- A5a is delegation verification only; continuous monitoring is A5b.
- `LIMES_ATTRIBUTION_AUTO_CONFIRM` now defaults to **on**. Auto-confirm still requires a fresh, verified delegation, and the flag can still turn it off.

## Scope

**In:**
- the verifier (`limes/intel/delegation.py`);
- a `delegation` fact kind;
- the `attribution_verify` passive-intel step;
- the delegation requirement in `apply_decisions`;
- verification in `rescore_assets --decide`;
- the flag default flip;
- verification status in the asset modal;
- adding `dnspython`.

**Out (later):**
- iterative resolution from the root for suffixes whose zone cut is not the PSL entry;
- IPv6 nameserver addresses;
- DNSSEC validation;
- verifying hostname candidates. They never carry NS facts today, so they never qualify.
- everything in A5b.

## Design

### 1. Verifier (`limes/intel/delegation.py`, new)

`verify(domain, control_ns, query=_udp_query, resolve=_resolve_a) -> (ok: bool, reason: str)`

The function is pure apart from the two injected I/O functions:
- `query(qname, rdtype, server_ip)` sends one UDP DNS query with RD=0 and returns a `dns.message.Message`, or raises on timeout or error.
- `resolve(name, rdtype)` is a recursive lookup through the system resolver and returns a list of strings.

`control_ns` is the sorted tuple of NS hosts that scoring used as control. Every name in it is under an owned root.

1. **Parent servers.** Take `suffix = domain.split('.', 1)[1]` for the registrable domain (e.g. `example.co.uk` → `co.uk`). Resolve `suffix NS` recursively, then each server's A record. Keep the first `MAX_SERVERS = 2` addresses in sorted name order. If none are found, fail with `'no parent servers'`.
2. **Parent delegation.** Send `domain NS` to the first parent server that answers (timeouts fall through to the next one). The response must meet all of these:
   - rcode NOERROR;
   - the AA flag is **not** set (a referral, not an answer);
   - an NS RRset in the authority section whose owner name equals `domain`.

   The delegated set, lowercased with the trailing dot stripped and sorted, must equal `control_ns`. Failure reasons:
   - `'parent unreachable'`;
   - `'no delegation at parent'`, which covers an AA answer, a missing NS, a referral to a different owner, and NXDOMAIN;
   - `'parent delegates elsewhere: <set>'`.
3. **Authoritative SOA.** Resolve the A records of the delegated nameservers recursively. These are hosts under our owned roots, so an outsider cannot change them. Ask the first one that answers for `domain SOA` with RD=0. The response must meet all of these:
   - rcode NOERROR;
   - the AA flag set;
   - an SOA RRset in the answer section with owner `domain`.

   Failure reasons are `'nameservers unreachable'` and `'not authoritative'`.
4. Return `(True, 'delegation verified at <parent server name>')`.

Queries go only to TLD or registry servers and to our own nameservers, never to a server an outsider chose. As a fail-closed belt, any server address that `scope.is_reserved_ip` flags is skipped. That covers private, loopback, link-local and documentation ranges. The candidate's nameserver hosts are not put through `scope.may_contact`: it requires an inventoried, resolved hostname, and our nameserver hosts usually aren't inventoried, so every check would fail. (Amended while planning, 2026-10-15.)

Constants:
- `QUERY_TIMEOUT = 2` seconds;
- `MAX_SERVERS = 2` tried at each stage.

`NOTE:` a suffix whose zone cut differs from the PSL entry fails closed. Examples are multi-label registry suffixes, and private-suffix tenants such as `myorg.github.io`, whose platform answers authoritatively instead of referring. The upgrade path is to walk referrals from the root.

`NOTE:` IPv4 only. A nameserver with only an AAAA record fails with `'nameservers unreachable'`.

Exceptions from the injected functions count as unreachable and are never raised to the caller. An unexpected exception inside `verify` propagates, and the stage treats it as a step failure.

### 2. Fact kind (`startScan/asset_models.py`)

Add `('delegation', 'Delegation')` to `AssetFact.KINDS`, with a choices-only migration. The value is the verified NS set (`', '`-joined, sorted, the same format as the control contribution's value), and the source is `'parent'`. On a successful verification, upsert the fact and bump `last_seen`. On failure, delete the candidate's `delegation` facts (fail closed).

### 3. Verify step (`limes/tasks/attribution.py`)

Extract the existing pre-qualification in `apply_decisions` into `_qualifying_control(asset, fresh_after) -> control contribution | None`. It covers score ≥ `AUTO_CONFIRM`, hop-1 control, hop-1 corroboration, and fresh NS facts equal to the control value.

`verify_delegations(project, verify=delegation.verify) -> {'verified': n, 'unverified': m}`:
- Candidates: `scope_tier='candidate'`, `kind='root_domain'`, `confidence >= AUTO_CONFIRM`, ordered by confidence descending. Cap at `MAX_VERIFY = 25` per run.
  - `NOTE:` candidates beyond the cap wait for the next run. The ceiling is 25 × 2 stages × 2 servers × 2s, which is at most 200s.
- For each candidate where `_qualifying_control` returns a control, call `verify(a.value, tuple(control NS hosts))`.
- Write the fact as described in section 2.
- Store `confidence_detail['delegation'] = {'ok': bool, 'reason': str, 'checked_at': iso}`. Use a conditional update on `scope_tier='candidate'` so a concurrent human decision wins.

### 4. Decisions

`apply_decisions` additionally requires a `delegation` fact on the asset whose value equals `control['value']` and whose `last_seen` is within `NS_FRESH`. Without one, the candidate is left alone: no tier change and no `would_auto_confirm` flag.

- With the flag on, verified candidates are auto-confirmed. The reason gains `; delegation verified at parent`.
- With the flag off, verified candidates get `would_auto_confirm=True`, as before.

### 5. Where it runs

- **Passive-intel steps:** `... attribution_dns, attribution_score, attribution_verify, attribution_decide`. `attribution_decide` is skipped if any of `attribution_dns`, `attribution_score` or `attribution_verify` failed.
- **`rescore_assets --decide`:** runs `verify_delegations` before `apply_decisions`. Without `--decide` it still only scores, and makes no network calls.

### 6. Setting (`limes/settings.py`)

`ATTRIBUTION_AUTO_CONFIRM = env.bool('LIMES_ATTRIBUTION_AUTO_CONFIRM', default=True)`.

### 7. UI (`static/custom/asset.js`)

The confidence block shows the delegation status from `confidence_detail.delegation`:
- verified: "Delegation verified at the registry";
- otherwise: "Delegation not verified: <reason>".

All text goes through `asset_esc`. The `would_auto_confirm` note becomes "Would auto-confirm (delegation verified); auto-confirm is disabled."

### 8. Dependency

Add `dnspython==2.6.1` to `web/requirements.txt`. dnsx cannot send RD=0 queries to a chosen server and expose the AA flag and authority section reliably, and the stdlib has no DNS client.

## Data flow

Candidate → `collect_dns` (child NS through the recursive resolver) → `score_project` (control from NS under owned roots) → `verify_delegations`:

1. parent referral equals the control set;
2. our nameserver answers SOA with AA set;
3. `delegation` fact written.

→ `apply_decisions` (fresh delegation fact plus the flag) → `owned_root`.

## Testing

All verifier tests use injected `query` and `resolve` functions built from `dns.message.make_response`. None touch the network.

**Verifier:**
- referral matches, then the SOA has AA set → ok;
- referral to a different set → `parent delegates elsewhere`;
- parent answers with AA set → `no delegation`;
- NXDOMAIN → `no delegation`;
- referral owner is a different name → `no delegation`;
- the first parent server times out and the second refers → ok;
- every parent server times out → `parent unreachable`;
- SOA without AA → `not authoritative`;
- nameservers time out → `nameservers unreachable`;
- nameserver resolving to a reserved address is never queried → `nameservers unreachable`;
- private-suffix tenant (`myorg.github.io`, platform answers with AA) → `no delegation`.

**Verify step:**
- writes the fact on success and deletes it on failure;
- skips non-qualifying candidates;
- respects `MAX_VERIFY` and confidence ordering;
- a human decision made between selection and the update is not overwritten.

**Decisions:**
- flag on with a verified fresh fact → confirmed;
- flag on, qualifying, no fact → stays a candidate with no flag;
- stale fact → stays;
- fact value differs from control → stays;
- flag off with a verified fact → `would_auto_confirm`.

**Stage:**
- verify fails → decide not called;
- order of steps.

**Command:**
- `--decide` calls verify, then decide;
- without it, neither runs.

## Review focus

1. A parent referral that carries our NS set alongside the outsider's (a partial overlap) must fail, because the set must be equal.
2. Case and trailing dots in NS names from the referral must not cause false mismatches, or false matches.
3. A candidate confirmed or rejected by a human while verification runs must keep the human decision.
4. A slow or black-holed registry must not stall passive intel past its soft time limit. The stage limit is 1h with a 58-minute soft limit (`limes/celery_routing.py`). Today's worst case is crt.sh, InternetDB and RIPEstat, plus 600s of dnsx, plus 200s of verification, which leaves headroom. The soft-limit handler still marks the step failed, so decide is skipped.
5. If the delegation is removed after verification, auto-confirm must stop within `NS_FRESH`. The next failed verify deletes the fact; a candidate that is not re-checked ages out.

## Risks

- **Vanity nameservers on a shared DNS provider.** If `ns1.ourco.com` is a CNAME to, or shares IPs with, a multi-tenant DNS provider, that provider may answer with AA set for another customer's zone. An outsider could then register a zone on the same provider and point their registry delegation at `ns1.ourco.com`. This is the remaining residual. It needs our nameserver hostnames, which an outsider can see, plus an account on the same provider. Decisions are audited and reversible. The upgrade path is to compare the SOA MNAME and RNAME against our owned zones' SOA.
- **Registry anycast and response-rate limiting.** At most 25 candidates per run, two queries each, at a 2s timeout is well inside normal registry tolerances.
- **Resolver trust.** The parent servers' addresses and our nameservers' addresses come from the system recursive resolver. A poisoned resolver could steer queries, but poisoning it is outside an outsider's normal reach. DNSSEC validation is the upgrade path.
- **Parent and child NS sets that legitimately differ.** This was seen live while planning: the `io` registry delegates `github.io` to five servers, but the zone lists a different set. Such domains never auto-confirm and stay in the review queue for a human. This is accepted, because equality is what makes partial-overlap spoofing fail.
