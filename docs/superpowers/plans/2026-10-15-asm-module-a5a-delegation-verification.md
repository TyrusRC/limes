# ASM module A5a — Delegation verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Auto-confirm a candidate domain only after the registry is shown to delegate it to our nameservers, and one of those nameservers answers authoritatively for the zone. Then turn auto-confirm on by default.

**Architecture:**
- A new pure module, `web/limes/intel/delegation.py`, does the check with dnspython. It takes injected query and resolve functions so tests never touch the network. It asks the registry servers for the candidate's NS records non-recursively (RD=0), then asks the delegated nameservers for the zone's SOA. It never sends a query to a reserved address.
- `web/limes/tasks/attribution.py` gains `verify_delegations`, which runs on qualifying candidates (at most 25). It records an `AssetFact(kind='delegation')` on success and deletes it on failure.
- `apply_decisions` now requires a fresh delegation fact that matches the control NS set.
- The check runs as a new `attribution_verify` passive-intel step, and inside `rescore_assets --decide`.

**Tech Stack:** Django 3.2, Celery 5.4, PostgreSQL, dnspython 2.6.1.

**Spec:** `docs/superpowers/specs/2026-10-15-asm-module-a5a-delegation-verification-design.md`

## Global Constraints

- **Verifier constants:** `QUERY_TIMEOUT = 2` seconds, `MAX_SERVERS = 2` per stage, `MAX_VERIFY = 25` candidates per run, ordered by confidence descending, then `id`. The ceiling is 200s.
- **Pass condition:** the delegated NS set from the parent referral (lowercased, trailing dot stripped, sorted) must **equal** the control NS set. The parent response must be NOERROR, **without** AA, with an authority NS RRset owned by the domain. The SOA response must be NOERROR **with** AA and carry an answer SOA owned by the domain. Everything else fails closed.
- **Reserved addresses:** a server address that `limes.scope.is_reserved_ip` flags is never queried.
- **Fact format:** `kind='delegation'`, `source='parent'`, value in the same format as the control contribution's value (`', '`-joined sorted NS hosts). Freshness is `NS_FRESH` (24h).
- **Concurrent human decisions:** only `candidate` assets are written, with conditional updates (`filter(pk=..., scope_tier='candidate')`). A concurrent human decision always wins.
- `LIMES_ATTRIBUTION_AUTO_CONFIRM` defaults to `True`.
- **Never swallow `SoftTimeLimitExceeded`:** the verifier catches only `dns.exception.DNSException` and `OSError`.
- **Migrations:** generate with `makemigrations`. The final `makemigrations --check` must be clean.
- **Style:**
  - tabs in `stages.py` and `asset.js`;
  - 4 spaces in `attribution.py`, `delegation.py`, `startScan/*`, tests and the management command.
- **Tests:**
  - `docker compose -p limes-test -f docker-compose.test.yml run --rm test python3 manage.py test <dotted.path>`; the controller may use an equivalent local runner.
  - No test touches the network.
  - The test image must be rebuilt after `requirements.txt` changes (`--build`).
- **Commits:** identity `TyrusRC <63230297+TyrusRC@users.noreply.github.com>`, no AI attribution, no push without an explicit user yes.

## Review Focus

1. **Partial overlap:** a parent referral listing our NS plus an outsider's must fail. Test: Task 1 `test_partial_overlap_fails`.
2. **Case and trailing dots** in NS names from the referral or the domain must not cause false results. Test: Task 1 `test_names_compare_case_and_dot_insensitive`.
3. **Human decision lands during verification:** it must be kept. Test: Task 2 `test_human_decision_during_verification_wins`.
4. **Delegation fact for another NS set, or older than 24h:** it must never confirm. Tests: Task 2 `test_delegation_for_another_ns_set_never_confirms` and `test_stale_delegation_never_confirms`.
5. **A failed verify step must skip decide**, and a re-score must not erase the last verification status shown to the user. Tests: Task 3 `test_never_decides_when_verification_fails` and Task 2 `test_rescore_keeps_last_delegation_status`.

## Rulings made while planning

- `scope.may_contact` is **not** used for nameserver hosts. It requires an inventoried, resolved hostname, and our nameserver hosts usually aren't inventoried, so every check would fail. The spec has been amended: any address that `is_reserved_ip` flags is skipped instead.
- `score_project` keeps the previous `confidence_detail['delegation']` so the last registry result stays visible after a re-score without `--decide`.
- A live check while planning showed that `bbc.co.uk` verifies through `dns1.nic.uk`. `github.io` fails because the `io` registry's NS set differs from the zone's own set. That is fail closed, and it is listed in the spec's Risks.
- The plan's code blocks were dry-run in a throwaway worktree before review. The full core suite passed (404 tests), `makemigrations --check` was clean, and `node --check asset.js` passed.

---
### Task 1: Registry delegation verifier

**Files:**
- Create: `web/limes/intel/delegation.py`
- Create: `web/tests/core/test_delegation.py`
- Modify: `web/requirements.txt` (add `dnspython==2.6.1` on its own line directly before `dotted-dict==1.1.3`)

**Interfaces:**
- Consumes: `limes.scope.is_reserved_ip(value) -> bool` (existing).
- Produces: `limes.intel.delegation.verify(domain: str, control_ns: Sequence[str], query=_udp_query, resolve=_resolve) -> tuple[bool, str]`. The reason strings are exactly:
  - `'no parent servers'`
  - `'parent unreachable'`
  - `'no delegation at parent'`
  - `'parent delegates elsewhere: <a, b>'`
  - `'nameservers unreachable'`
  - `'not authoritative'`
  - `'delegation verified at <parent ns host>'`

- [ ] **Step 1: Add the dependency and write the failing tests**

Add `dnspython==2.6.1` to `web/requirements.txt` directly before `dotted-dict==1.1.3`. Create `web/tests/core/test_delegation.py`:

```python
from django.test import SimpleTestCase

import dns.exception
import dns.flags
import dns.message
import dns.rcode
import dns.rrset

from limes.intel import delegation

PARENT = {'a.gtld-servers.net': '192.5.6.30', 'b.gtld-servers.net': '192.33.14.30'}
RESERVED = {'ns1.inside.example': '10.0.0.53'}
OURS = {'ns1.example.com': '45.33.10.1', 'ns2.example.com': '45.33.10.2'}


def fake_resolve(name, rdtype):
    if rdtype == 'NS':
        return {'net': sorted(PARENT), 'io': ['ns-tld.io'], 'github.io': ['dns1.p05.nsone.net']}.get(name, [])
    return [ip] if (ip := {**PARENT, **OURS, **RESERVED, 'ns-tld.io': '65.22.160.17', 'dns1.p05.nsone.net': '198.51.44.5'}.get(name)) else []


def referral(qname, ns, rcode=dns.rcode.NOERROR, aa=False, owner=None):
    r = dns.message.make_response(dns.message.make_query(qname, 'NS'))
    r.set_rcode(rcode)
    if aa:
        r.flags |= dns.flags.AA
    if ns:
        r.authority.append(dns.rrset.from_text(owner or qname, 3600, 'IN', 'NS', *[h + '.' for h in ns]))
    return r


def soa(qname, aa=True):
    r = dns.message.make_response(dns.message.make_query(qname, 'SOA'))
    if aa:
        r.flags |= dns.flags.AA
    r.answer.append(dns.rrset.from_text(qname, 3600, 'IN', 'SOA', 'ns1.example.com. hostmaster.example.com. 1 7200 900 1209600 300'))
    return r


class FakeDNS:
    """Answers by server IP; an exception instance in the table is raised (a timeout)."""

    def __init__(self, table):
        self.table, self.asked = table, []

    def __call__(self, qname, rdtype, ip):
        self.asked.append((qname, rdtype, ip))
        out = self.table.get((rdtype, ip))
        if isinstance(out, Exception):
            raise out
        if out is None:
            raise dns.exception.Timeout()
        return out


OK = ('ns1.example.com', 'ns2.example.com')


def ours_ok(qname='ours.net', ns=OK):
    return {('NS', '192.5.6.30'): referral(qname, ns), ('SOA', '45.33.10.1'): soa(qname)}


class VerifyTest(SimpleTestCase):
    def check(self, table, domain='ours.net', control=OK):
        fake = FakeDNS(table)
        return delegation.verify(domain, control, query=fake, resolve=fake_resolve), fake

    def test_matching_referral_and_authoritative_soa(self):
        (ok, reason), fake = self.check(ours_ok())
        self.assertEqual((ok, reason), (True, 'delegation verified at a.gtld-servers.net'))
        self.assertEqual({ip for _, _, ip in fake.asked}, {'192.5.6.30', '45.33.10.1'})  # registry + ours only

    def test_names_compare_case_and_dot_insensitive(self):
        (ok, _), _ = self.check(ours_ok(ns=('NS2.Example.COM', 'ns1.example.com')), domain='Ours.NET.')
        self.assertTrue(ok)

    def test_parent_delegates_elsewhere(self):
        (ok, reason), _ = self.check(ours_ok(ns=('ns1.attacker.net',)))
        self.assertEqual((ok, reason), (False, 'parent delegates elsewhere: ns1.attacker.net'))

    def test_partial_overlap_fails(self):
        (ok, _), _ = self.check(ours_ok(ns=OK + ('ns1.attacker.net',)))
        self.assertFalse(ok)

    def test_authoritative_answer_at_parent_is_not_a_delegation(self):
        (ok, reason), _ = self.check({('NS', '192.5.6.30'): referral('ours.net', OK, aa=True)})
        self.assertEqual((ok, reason), (False, 'no delegation at parent'))

    def test_nxdomain_and_foreign_owner_are_not_delegations(self):
        for resp in (referral('ours.net', None, rcode=dns.rcode.NXDOMAIN), referral('ours.net', OK, owner='other.net')):
            (ok, reason), _ = self.check({('NS', '192.5.6.30'): resp})
            self.assertEqual((ok, reason), (False, 'no delegation at parent'))

    def test_first_parent_timeout_falls_through(self):
        table = ours_ok()
        table[('NS', '192.33.14.30')] = table.pop(('NS', '192.5.6.30'))
        (ok, reason), _ = self.check(table)
        self.assertEqual((ok, reason), (True, 'delegation verified at b.gtld-servers.net'))

    def test_all_parents_unreachable(self):
        (ok, reason), _ = self.check({('NS', '192.5.6.30'): OSError('unreachable')})
        self.assertEqual((ok, reason), (False, 'parent unreachable'))

    def test_soa_without_aa_is_not_authoritative(self):
        table = ours_ok()
        table[('SOA', '45.33.10.1')] = soa('ours.net', aa=False)
        (ok, reason), _ = self.check(table)
        self.assertEqual((ok, reason), (False, 'not authoritative'))

    def test_nameservers_unreachable(self):
        table = ours_ok()
        del table[('SOA', '45.33.10.1')]
        (ok, reason), _ = self.check(table)
        self.assertEqual((ok, reason), (False, 'nameservers unreachable'))

    def test_private_suffix_tenant_fails_closed(self):
        # the platform answers for its tenants itself: no referral
        tenant = 'myorg.github.io'
        resp = referral(tenant, None, aa=True)
        (ok, reason), _ = self.check({('NS', '198.51.44.5'): resp}, domain=tenant)
        self.assertEqual((ok, reason), (False, 'no delegation at parent'))

    def test_unknown_suffix_has_no_parent_servers(self):
        (ok, reason), _ = self.check({}, domain='ours.invalid')
        self.assertEqual((ok, reason), (False, 'no parent servers'))

    def test_reserved_nameserver_address_is_never_queried(self):
        inside = ('ns1.inside.example',)
        table = {('NS', '192.5.6.30'): referral('ours.net', inside), ('SOA', '10.0.0.53'): soa('ours.net')}
        (ok, reason), fake = self.check(table, control=inside)
        self.assertEqual((ok, reason), (False, 'nameservers unreachable'))
        self.assertNotIn('10.0.0.53', {ip for _, _, ip in fake.asked})
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `... python3 manage.py test tests.core.test_delegation` (rebuild the test image first: dnspython is new).
Expected: ERROR, `ImportError: cannot import name 'delegation' from 'limes.intel'`.

- [ ] **Step 3: Write the verifier**

Create `web/limes/intel/delegation.py`:

```python
"""Registry-level delegation check for attribution auto-confirm (A5a).

A recursive NS answer is the child zone's own claim. This asks the parent (registry) servers
non-recursively who the zone is delegated to, then asks those nameservers - ours - for an
authoritative SOA. Queries go only to registry servers and the delegated nameservers, and never
to a private or reserved address.
"""
import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver

from limes.scope import is_reserved_ip

QUERY_TIMEOUT = 2  # seconds per query
MAX_SERVERS = 2  # servers tried at each stage

# NOTE: the parent is taken as the registrable domain's public suffix. A suffix whose zone cut
# differs from the PSL entry (multi-label registry suffixes, private-suffix tenants such as
# myorg.github.io) fails closed. Upgrade path: walk referrals from the root.
# NOTE: IPv4 only; a nameserver with only AAAA records is unreachable here.


def _norm(name):
    return str(name).rstrip('.').lower()


def _udp_query(qname, rdtype, server_ip):
    q = dns.message.make_query(qname, rdtype)
    q.flags &= ~dns.flags.RD
    return dns.query.udp(q, server_ip, timeout=QUERY_TIMEOUT)


def _resolve(name, rdtype):
    try:
        return [_norm(r.to_text()) for r in dns.resolver.resolve(name, rdtype, lifetime=QUERY_TIMEOUT * 2)]
    except dns.exception.DNSException:
        return []


def _addresses(hosts, resolve):
    out = []
    for host in sorted(hosts):
        ips = [ip for ip in resolve(host, 'A') if not is_reserved_ip(ip)]
        if ips:
            out.append((host, ips[0]))
        if len(out) == MAX_SERVERS:
            break
    return out


def _ask(servers, qname, rdtype, query):
    """First answer from the servers in order; timeouts and network errors fall through."""
    for host, ip in servers:
        try:
            return host, query(qname, rdtype, ip)
        except (dns.exception.DNSException, OSError):
            continue
    return None, None


def _rrset(section, owner, rdtype):
    return next((rr for rr in section if rr.rdtype == rdtype and _norm(rr.name) == owner), None)


def verify(domain, control_ns, query=_udp_query, resolve=_resolve):
    """(ok, reason): the registry delegates `domain` to exactly `control_ns`, and one of them
    answers authoritatively (AA) with the zone's SOA. Anything else fails closed."""
    domain = _norm(domain)
    want = tuple(sorted(_norm(h) for h in control_ns))
    suffix = domain.split('.', 1)[1] if '.' in domain else ''
    parents = _addresses(resolve(suffix, 'NS'), resolve) if suffix else []
    if not parents:
        return False, 'no parent servers'
    parent, resp = _ask(parents, domain, 'NS', query)
    if resp is None:
        return False, 'parent unreachable'
    ns = _rrset(resp.authority, domain, dns.rdatatype.NS)
    if resp.rcode() != dns.rcode.NOERROR or resp.flags & dns.flags.AA or ns is None:
        return False, 'no delegation at parent'
    got = tuple(sorted(_norm(r.target) for r in ns))
    if got != want:
        return False, f'parent delegates elsewhere: {", ".join(got)}'
    _, soa = _ask(_addresses(got, resolve), domain, 'SOA', query)
    if soa is None:
        return False, 'nameservers unreachable'
    if soa.rcode() != dns.rcode.NOERROR or not soa.flags & dns.flags.AA or _rrset(soa.answer, domain, dns.rdatatype.SOA) is None:
        return False, 'not authoritative'
    return True, f'delegation verified at {parent}'
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `... python3 manage.py test tests.core.test_delegation`
Expected: 13 tests OK.

- [ ] **Step 5: Commit**

```bash
git add web/requirements.txt web/limes/intel/delegation.py web/tests/core/test_delegation.py
git commit -m "Add a registry delegation check for attribution auto-confirm

A recursive NS answer is the zone owner's own claim. Ask the registry
who the zone is delegated to and require our nameservers to answer
authoritatively, so an outsider cannot borrow our nameserver names."
```

### Task 2: Delegation fact, verify step, verified decisions, default on

**Files:**
- Modify: `web/startScan/asset_models.py` (`AssetFact.KINDS` gains `'delegation'`). Generate the migration with `python3 manage.py makemigrations startScan -n assetfact_delegation_kind`; it should be `0016_assetfact_delegation_kind.py`.
- Modify: `web/limes/tasks/attribution.py` (imports, `MAX_VERIFY`, `_qualifying_control`, `verify_delegations`, `score_project` keeps `delegation`, `apply_decisions`)
- Modify: `web/limes/settings.py:32` (default `True`)
- Test: `web/tests/core/test_attribution_decisions.py`

**Interfaces:**
- Consumes: `delegation.verify(domain, control_ns) -> (ok, reason)` from Task 1. It is looked up at call time (`verify or delegation.verify`) so tests can patch `limes.intel.delegation.verify`.
- Produces:
  - `attribution.verify_delegations(project, verify=None) -> {'verified': int, 'unverified': int}`.
  - `attribution.MAX_VERIFY = 25`.
  - `confidence_detail['delegation'] = {'ok': bool, 'reason': str, 'checked_at': iso str}`.
  - `apply_decisions` requires a fresh matching `delegation` fact. Its reason ends with `; delegation verified at parent`.

- [ ] **Step 1: Write the failing tests**

In `web/tests/core/test_attribution_decisions.py`:

(a) Add a helper to `DecisionBase`, after `cand`:

```python
    def delegate(self, a, value='ns1.example.com'):
        inventory.record_fact(a, 'delegation', value, 'parent')
```

(b) Decorate `DisabledAutoConfirmTest` with `@override_settings(ATTRIBUTION_AUTO_CONFIRM=False)`. The default is now on. In `test_qualifying_candidate_is_only_flagged` and `test_rescore_clears_a_stale_flag`, add `self.delegate(a)` on the line after `a = self.cand(...)`.

(c) In `DecisionTest`, add `self.delegate(a)` right after `a = self.cand(...)` in these tests:
- `test_working_ns_control_plus_cert_auto_confirms`;
- `test_rescore_command_decides_on_request`;
- `test_stale_ns_facts_never_auto_confirm`;
- `test_concurrent_source_provenance_is_kept`.

In `test_working_ns_control_plus_cert_auto_confirms`, also add:

```python
        self.assertIn('delegation verified at parent', a.decision_reason)
```

(d) Append these tests to `DecisionTest`:

```python
    def test_qualifying_without_verified_delegation_stays_candidate(self):
        a = self.cand('unverified.net', ('ns', 'ns1.example.com', 'dns'), ('cert', '102', 'crtsh'))
        self.assertEqual(self.run_all(), {'auto_confirmed': 0, 'would_auto_confirm': 0})
        self.assertEqual(self.tier(a), 'candidate')
        self.assertNotIn('would_auto_confirm', a.confidence_detail)

    def test_stale_delegation_never_confirms(self):
        a = self.cand('old.net', ('ns', 'ns1.example.com', 'dns'), ('cert', '102', 'crtsh'))
        self.delegate(a)
        AssetFact.objects.filter(asset=a, kind='delegation').update(last_seen=timezone.now() - timedelta(hours=25))
        self.assertEqual(self.run_all(), {'auto_confirmed': 0, 'would_auto_confirm': 0})
        self.assertEqual(self.tier(a), 'candidate')

    def test_delegation_for_another_ns_set_never_confirms(self):
        a = self.cand('other.net', ('ns', 'ns1.example.com', 'dns'), ('cert', '102', 'crtsh'))
        self.delegate(a, 'ns1.example.com, ns9.example.com')
        self.assertEqual(self.run_all(), {'auto_confirmed': 0, 'would_auto_confirm': 0})
        self.assertEqual(self.tier(a), 'candidate')
```

(e) Append a new class at the end of the file:

```python
class VerifyDelegationsTest(DecisionBase):
    def qualifying(self, value):
        return self.cand(value, ('ns', 'ns1.example.com', 'dns'), ('cert', '102', 'crtsh'))

    def verify(self, *_):
        return True, 'delegation verified at a.gtld-servers.net'

    def test_success_records_fact_and_status(self):
        a = self.qualifying('ours.net')
        attribution.score_project(self.p)
        calls = []
        out = attribution.verify_delegations(self.p, verify=lambda d, ns: calls.append((d, list(ns))) or self.verify())
        self.assertEqual(out, {'verified': 1, 'unverified': 0})
        self.assertEqual(calls, [('ours.net', ['ns1.example.com'])])
        fact = AssetFact.objects.get(asset=a, kind='delegation')
        self.assertEqual((fact.value, fact.source), ('ns1.example.com', 'parent'))
        a.refresh_from_db()
        self.assertEqual(a.confidence_detail['delegation']['ok'], True)
        self.assertEqual(a.confidence_detail['delegation']['reason'], 'delegation verified at a.gtld-servers.net')

    def test_failure_deletes_fact_and_records_reason(self):
        a = self.qualifying('ours.net')
        self.delegate(a)
        attribution.score_project(self.p)
        out = attribution.verify_delegations(self.p, verify=lambda d, ns: (False, 'not authoritative'))
        self.assertEqual(out, {'verified': 0, 'unverified': 1})
        self.assertFalse(AssetFact.objects.filter(asset=a, kind='delegation').exists())
        a.refresh_from_db()
        self.assertEqual(a.confidence_detail['delegation']['reason'], 'not authoritative')

    def test_non_qualifying_candidates_are_never_checked(self):
        self.cand('nsonly.net', ('ns', 'ns1.example.com', 'dns'))  # no corroboration
        attribution.score_project(self.p)
        out = attribution.verify_delegations(self.p, verify=lambda d, ns: self.fail('checked'))
        self.assertEqual(out, {'verified': 0, 'unverified': 0})

    def test_cap_checks_highest_confidence_first(self):
        low, high = self.qualifying('low.net'), self.qualifying('high.net')
        attribution.score_project(self.p)
        Asset.objects.filter(pk=low.pk).update(confidence=0.91)
        seen = []
        with mock.patch.object(attribution, 'MAX_VERIFY', 1):
            attribution.verify_delegations(self.p, verify=lambda d, ns: seen.append(d) or self.verify())
        self.assertEqual(seen, ['high.net'])

    def test_human_decision_during_verification_wins(self):
        a = self.qualifying('race.net')
        attribution.score_project(self.p)

        def verify(d, ns):
            Asset.objects.filter(pk=a.pk).update(scope_tier='rejected')
            return self.verify()

        attribution.verify_delegations(self.p, verify=verify)
        a.refresh_from_db()
        self.assertEqual(a.scope_tier, 'rejected')
        self.assertNotIn('delegation', a.confidence_detail)

    def test_rescore_keeps_last_delegation_status(self):
        a = self.qualifying('ours.net')
        attribution.score_project(self.p)
        attribution.verify_delegations(self.p, verify=self.verify)
        attribution.score_project(self.p)
        a.refresh_from_db()
        self.assertTrue(a.confidence_detail['delegation']['ok'])
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `... python3 manage.py test tests.core.test_attribution_decisions`
Expected:
- `VerifyDelegationsTest` errors with `AttributeError: module 'limes.tasks.attribution' has no attribute 'verify_delegations'`.
- `test_qualifying_without_verified_delegation_stays_candidate`, `test_stale_delegation_never_confirms` and `test_delegation_for_another_ns_set_never_confirms` FAIL, because the candidate is confirmed.
- Recording a `delegation` fact raises no error before the kind is added: Django doesn't validate `choices` on `get_or_create`.

- [ ] **Step 3: Implement**

`web/startScan/asset_models.py`, in `AssetFact`:

```python
    KINDS = [(k, k) for k in ('cert', 'ip', 'ns', 'mx', 'delegation')]
```

Then run `python3 manage.py makemigrations startScan -n assetfact_delegation_kind`.

`web/limes/settings.py:31-32`, replace both lines with:

```python
# On: auto-confirm still needs a registry-verified delegation (limes.intel.delegation); false only flags
ATTRIBUTION_AUTO_CONFIRM = env.bool('LIMES_ATTRIBUTION_AUTO_CONFIRM', default=True)
```

`web/limes/tasks/attribution.py`:
- Change the imports `from limes import commands` and `from limes.intel import domains` to:

```python
from limes import commands
from limes.intel import delegation, domains
```

- Add after `NS_FRESH = ...`:

```python
MAX_VERIFY = 25  # NOTE: registry checks per run, highest confidence first; the rest wait (<= 25 x 2 x 2 x 2s = 200s)
```

- In `score_project`, replace

```python
        c.confidence_detail = {'version': VERSION, 'score': score, 'contributions': contribs}
```

with

```python
        prev = (c.confidence_detail or {}).get('delegation')
        c.confidence_detail = {'version': VERSION, 'score': score, 'contributions': contribs}
        if prev:
            c.confidence_detail['delegation'] = prev  # the last registry check stays visible until the next
```

- Replace the whole `apply_decisions` function with these three functions:

```python
def _qualifying_control(a, fresh_after):
    """a's hop-1 NS control contribution if a qualifies for auto-confirm on evidence: control plus
    corroboration, and current NS facts seen since fresh_after that equal that control. Else None."""
    contribs = (a.confidence_detail or {}).get('contributions') or []
    control = next((c for c in contribs if c.get('hop') == 1 and c.get('control')), None)
    if not control or not any(c.get('hop') == 1 and c.get('corroborates') for c in contribs):
        return None
    # re-derive control from current facts: scoring may predate a dropped or replaced delegation
    ns_now = AssetFact.objects.filter(asset=a, kind='ns')
    if (not ns_now.exists() or ns_now.filter(last_seen__lt=fresh_after).exists()
            or ', '.join(sorted(ns_now.values_list('value', flat=True))) != control['value']):
        return None
    return control


def verify_delegations(project, verify=None):
    """Ask the registry who each qualifying candidate is delegated to (limes.intel.delegation).
    Success records the 'delegation' fact apply_decisions requires; failure deletes it (fail closed)."""
    verify = verify or delegation.verify
    fresh_after = timezone.now() - NS_FRESH
    counts = {'verified': 0, 'unverified': 0}
    for a in Asset.objects.filter(project=project, scope_tier='candidate', kind='root_domain',
                                  confidence__gte=AUTO_CONFIRM).order_by('-confidence', 'id'):
        control = _qualifying_control(a, fresh_after)
        if not control:
            continue
        if sum(counts.values()) >= MAX_VERIFY:
            break
        ok, reason = verify(a.value, control['value'].split(', '))
        if ok:
            inventory.record_fact(a, 'delegation', control['value'], 'parent')
        else:
            AssetFact.objects.filter(asset=a, kind='delegation').delete()
        counts['verified' if ok else 'unverified'] += 1
        status = {'ok': ok, 'reason': reason, 'checked_at': timezone.now().isoformat()}
        Asset.objects.filter(pk=a.pk, scope_tier='candidate').update(
            confidence_detail={**a.confidence_detail, 'delegation': status})
    return counts


def apply_decisions(project):
    """Auto-confirm only score >= AUTO_CONFIRM with hop-1 NS control AND hop-1 corroboration, from NS
    facts seen within NS_FRESH, AND a registry-verified delegation of that same NS set seen within
    NS_FRESH (verify_delegations). The conditional update means a concurrent human decision wins.
    With settings.ATTRIBUTION_AUTO_CONFIRM off no tier changes: qualifying candidates are only
    flagged 'would_auto_confirm' for a human to review."""
    from dashboard.stats import invalidate
    auto = would = 0
    fresh_after = timezone.now() - NS_FRESH
    # hostname candidates never get NS facts today, so they never qualify
    for a in Asset.objects.filter(project=project, scope_tier='candidate', kind__in=('root_domain', 'hostname'),
                                  confidence__gte=AUTO_CONFIRM):
        control = _qualifying_control(a, fresh_after)
        if not control or not AssetFact.objects.filter(asset=a, kind='delegation', value=control['value'],
                                                       last_seen__gte=fresh_after).exists():
            continue
        if not settings.ATTRIBUTION_AUTO_CONFIRM:
            would += Asset.objects.filter(pk=a.pk, scope_tier='candidate').update(
                confidence_detail={**a.confidence_detail, 'would_auto_confirm': True})
            continue
        reason = (f'auto-confirmed ({VERSION}) {a.confidence:.2f}: NS {control["value"]} '
                  f'under owned root {control["via"]}; delegation verified at parent')
        # append to the sources as stored now, so provenance added concurrently is not overwritten
        a.sources = Asset.objects.filter(pk=a.pk).values_list('sources', flat=True).first() or []
        inventory._append_source(a, 'attribution', reason)
        tier = 'owned_root' if a.kind == 'root_domain' else 'owned_host'
        auto += Asset.objects.filter(pk=a.pk, scope_tier='candidate').update(
            scope_tier=tier, decision_reason=reason, sources=a.sources, added_by=None)
    if auto:
        invalidate(project.id)
    return {'auto_confirmed': auto, 'would_auto_confirm': would}
```

- Replace the module docstring's second paragraph `DNS lookups go to resolvers only, never to a target.` with:

```text
DNS lookups go to resolvers only, never to a target; delegation checks (verify_delegations) query
registry servers and our own nameservers only.
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `... python3 manage.py test tests.core.test_attribution_decisions tests.core.test_attribution_score tests.core.test_attribution_dns tests.core.test_delegation`.
Expected: all OK. Also run `python3 manage.py makemigrations --check --dry-run`, expected `No changes detected`.

- [ ] **Step 5: Commit**

```bash
git add web/startScan/asset_models.py web/startScan/migrations/0016_assetfact_delegation_kind.py web/limes/tasks/attribution.py web/limes/settings.py web/tests/core/test_attribution_decisions.py
git commit -m "Require a registry-verified delegation for auto-confirm and turn it on

Auto-confirm shipped off because NS control came from the zone's own
records. A delegation fact recorded only after the registry and our
nameservers agree now gates every decision, so the default is on."
```

### Task 3: Run verification in passive intel and `rescore_assets --decide`

**Files:**
- Modify: `web/limes/tasks/stages.py:241-250` (step list and decide skip)
- Modify: `web/startScan/management/commands/rescore_assets.py`
- Test: `web/tests/core/test_passive_intel_stage.py`, `web/tests/core/test_attribution_decisions.py`

**Interfaces:**
- Consumes: `attribution.verify_delegations(project) -> {'verified', 'unverified'}` from Task 2.
- Produces: the passive-intel step name `attribution_verify`.

- [ ] **Step 1: Write the failing tests**

In `web/tests/core/test_passive_intel_stage.py`, add this entry to the `mocks` dict in `patched()`, after `'score_project'`:

```python
            'verify_delegations': mock.patch('limes.tasks.attribution.verify_delegations', return_value={'verified': 0}),
```

Append to `PassiveIntelStageTest`:

```python
    def test_verifies_between_scoring_and_deciding(self):
        m = self.patched()
        order = mock.Mock()
        for name in ('score_project', 'verify_delegations', 'apply_decisions'):
            order.attach_mock(m[name], name)
        stages.passive_intel(ctx=dict(self.ctx))
        self.assertEqual([c[0] for c in order.mock_calls], ['score_project', 'verify_delegations', 'apply_decisions'])

    def test_never_decides_when_verification_fails(self):
        m = self.patched(verify_delegations=mock.patch('limes.tasks.attribution.verify_delegations',
                                                       side_effect=RuntimeError('registry')))
        out = stages.passive_intel(ctx=dict(self.ctx))
        m['apply_decisions'].assert_not_called()
        self.assertEqual(out['failed'], 'attribution_verify')
```

In `web/tests/core/test_attribution_decisions.py` (`DecisionTest`), replace the two command tests with:

```python
    def test_rescore_command_scores_only_by_default(self):
        a = self.cand('cmd.net', ('ns', 'ns1.example.com', 'dns'), ('cert', '102', 'crtsh'))
        out = StringIO()
        with mock.patch('limes.intel.delegation.verify', side_effect=AssertionError('network used')):
            call_command('rescore_assets', 'p', stdout=out)
        self.assertEqual(self.tier(a), 'candidate')
        self.assertGreaterEqual(a.confidence, 0.9)
        self.assertEqual(out.getvalue().strip(), 'scored=1')

    def test_rescore_command_verifies_then_decides_on_request(self):
        a = self.cand('cmd.net', ('ns', 'ns1.example.com', 'dns'), ('cert', '102', 'crtsh'))
        out = StringIO()
        with mock.patch('limes.intel.delegation.verify', return_value=(True, 'delegation verified at x')) as v:
            call_command('rescore_assets', 'p', '--decide', stdout=out)
        v.assert_called_once_with('cmd.net', ['ns1.example.com'])
        self.assertEqual(self.tier(a), 'owned_root')
        self.assertIn('verified=1', out.getvalue())
        self.assertIn('auto_confirmed=1', out.getvalue())
```

`test_rescore_command_decides_on_request` is replaced. Drop the `self.delegate(a)` that Task 2 added to it.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `... python3 manage.py test tests.core.test_passive_intel_stage tests.core.test_attribution_decisions`
Expected:
- `test_verifies_between_scoring_and_deciding` FAILs: the call list lacks `verify_delegations`.
- `test_never_decides_when_verification_fails` FAILs: `apply_decisions` is called.
- `test_rescore_command_verifies_then_decides_on_request` FAILs: `verify` is not called.

- [ ] **Step 3: Implement**

In `web/limes/tasks/stages.py`, add the step between score and decide:

```python
		('attribution_score', lambda: attribution.score_project(project)),
		('attribution_verify', lambda: attribution.verify_delegations(project)),
		('attribution_decide', lambda: attribution.apply_decisions(project)),
```

Then change the skip to:

```python
		if name == 'attribution_decide' and {'attribution_dns', 'attribution_score', 'attribution_verify'} & set(failed):
			continue  # facts, scores or delegations may be stale or partial: never decide from them
```

`web/startScan/management/commands/rescore_assets.py`: change the help text, the `--decide` help and the decide branch:

```python
    help = ('Re-score candidate ownership with the current attribution weights '
            '(--decide also verifies delegations at the registry and applies decisions).')

    def add_arguments(self, parser):
        parser.add_argument('project_slug')
        parser.add_argument('--decide', action='store_true',
                            help='also query the registry for delegations (network) and apply auto-confirm decisions')
```

```python
        if options['decide']:
            counts = {**counts, **attribution.verify_delegations(project), **attribution.apply_decisions(project)}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `... python3 manage.py test tests.core.test_passive_intel_stage tests.core.test_attribution_decisions`
Expected: all OK.

- [ ] **Step 5: Commit**

```bash
git add web/limes/tasks/stages.py web/startScan/management/commands/rescore_assets.py web/tests/core/test_passive_intel_stage.py web/tests/core/test_attribution_decisions.py
git commit -m "Verify delegations before every attribution decision

Passive intel and rescore_assets --decide now ask the registry between
scoring and deciding, and a failed check skips decisions like a failed
DNS or scoring step does."
```

### Task 4: Show the delegation result in the asset modal

**Files:**
- Modify: `web/static/custom/asset.js` (`asset_confidence_html`, lines 82-94)

**Interfaces:**
- Consumes: `confidence_detail.delegation = {ok, reason, checked_at}` from Task 2, exposed unchanged by the existing asset API.

- [ ] **Step 1: Implement**

In `web/static/custom/asset.js`, replace the `return` statement of `asset_confidence_html` with:

```javascript
	var dg = d.delegation, delegation = '';
	if (dg && typeof dg === 'object') {
		delegation = '<p class="' + (dg.ok === true ? 'text-success' : 'text-muted') + '">' +
			asset_esc(dg.ok === true ? 'Delegation verified at the registry' : 'Delegation not verified: ' + dg.reason) + '</p>';
	}
	return '<h5>Confidence ' + asset_esc(Number(d.score).toFixed(2)) + ' <small class="text-muted">(' +
		asset_esc(d.version) + ')</small></h5><table class="table table-sm"><thead><tr><th>Evidence</th><th>Value</th>' +
		'<th>Via</th><th>Weight</th><th>Hop</th></tr></thead><tbody>' + rows + '</tbody></table>' + delegation +
		(d.would_auto_confirm === true ? '<p class="text-warning">' +
			asset_esc('Would auto-confirm (delegation verified); auto-confirm is disabled.') + '</p>' : '');
```

- [ ] **Step 2: Verify in the real UI**

There is no JS unit-test harness. Drive the real flow:
1. Start the dev server.
2. Create a candidate whose `confidence_detail` is `{'version': 'attribution-v1', 'score': 0.97, 'contributions': [], 'delegation': {'ok': False, 'reason': '<img src=x onerror=alert(1)>not authoritative', 'checked_at': '2026-10-15T00:00:00Z'}}`. A second candidate gets `'delegation': {'ok': True, ...}` and `'would_auto_confirm': True`.
3. Open each one's modal on the Assets page.

Expected:
- The first shows "Delegation not verified: <img src=x onerror=alert(1)>not authoritative" as literal text: no image element, no dialog.
- The second shows "Delegation verified at the registry" and the new would-auto-confirm sentence.
- The browser console has no errors.

- [ ] **Step 3: Commit**

```bash
git add web/static/custom/asset.js
git commit -m "Show the registry delegation check in the asset modal"
```
