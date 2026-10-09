# ASM module A3a — DNS resolution + IP scope guard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve every discovered host with dnsx, record resolved IPs as `dependency` unless provably owned, and refuse — failing closed — every stage that would send traffic to an out-of-scope target or into private/reserved address space.

**Architecture:** A pure `limes/scope.py` owns the reserved ranges and two guard levels (`may_contact`, `may_attack`); every traffic-sending stage filters its own target list through it before writing the tool's input file. A pure `limes/pipeline/dnsx.py` builds argv/parses JSON; `limes/tasks/resolution.py` runs it inside `subdomain_discovery`, before the httpx probe, writing through `inventory.record_resolution`. IP ownership is inferred on upsert (`dependency` unless inside an owned IP/CIDR asset); a data migration demotes previously auto-owned IPs.

**Tech Stack:** Django 3.2, Celery 5.4, PostgreSQL, Python `ipaddress`, ProjectDiscovery dnsx (already in the image).

**Spec:** `docs/superpowers/specs/2026-10-09-asm-module-a3a-resolve-scope-guard-design.md`

## Global Constraints

- Tools run with argv lists via `limes.commands.run` — never `shell=True`, never an f-string command.
- Fail closed: a missing project, missing asset, missing resolution or any exception in a scope check refuses the target.
- Upsert never changes an existing IP asset's `scope_tier` (no downgrade, no promotion).
- `code_audit` is not guarded (no network traffic). `port_scan` and `nmap` use `allow_co_brand=False`.
- Migrations are generated with `makemigrations` (never hand-written schema ops); data migrations are `RunPython` with a no-op reverse. Final `makemigrations --check --dry-run` → "No changes detected".
- Match file style: tabs in `limes/tasks/*.py`, 4 spaces in `limes/scope.py`, `limes/pipeline/*.py`, `startScan/*`, `api/asset_add.py`, tests.
- Tests: `docker compose -p limes-test -f docker-compose.test.yml run --rm test python3 manage.py test <dotted.path>` (whole suite: `make test`).
- Commit identity `TyrusRC <63230297+TyrusRC@users.noreply.github.com>`; no AI attribution; no push without an explicit user yes.

## Review Focus

1. **Discovery wiring order** — `resolution.resolve_root` must run before `http_crawl` inside `subdomain_discovery`; if it runs after (or not at all) the contact guard refuses every new host and the probe silently does nothing. No unit test drives the whole discovery stage: the reviewer must read the call order (Task 6 Step 7 makes it a single adjacent block).
2. **Guard falls back to "all"** — a stage that, after filtering to an empty list, falls back to its DB helper (e.g. `port_scan`'s `get_subdomains`) would scan everything. Each guarded stage must return early on an empty allowed list → Task 7 tests "all refused → tool never invoked".
3. **Stale input file** — stages write their input file before filtering today (`http_crawl` even filters exclusions after writing). Each guarded stage must write/rewrite the file from the allowed list → Task 7 tests read the file the tool receives.
4. **Stale dnsx output** — a failed dnsx run must not re-read the previous run's `dnsx.jsonl` → `resolve_root` deletes it before each run; Task 6 `test_failed_run_records_nothing_and_ignores_stale_output`.
5. **IPv4-mapped / bracketed IPv6 targets** — `http://[::ffff:10.0.0.1]/` must be treated as 10.0.0.1 → Task 1 `target_host` + `is_reserved_ip` tests.

---

### Task 1: `limes/scope.py` core — reserved ranges, IP parsing, target host extraction

**Files:**
- Create: `web/limes/scope.py`
- Modify: `web/api/asset_add.py` (use the shared definitions; behaviour unchanged)
- Test: `web/tests/core/test_scope.py` (create)

**Interfaces:**
- Produces: `RESERVED_NETWORKS: list[ip_network]`; `parse_ip(value) -> ip_address | None` (collapses IPv4-mapped IPv6); `is_reserved_ip(value) -> bool` (unparseable → True); `is_reserved_network(net) -> bool`; `target_host(target: str) -> str | None` (URL, `host:port`, bracketed IPv6 or bare host → lower-case host without trailing dot).

- [ ] **Step 1: Write the failing tests** (`web/tests/core/test_scope.py`):
```python
import ipaddress

from django.test import SimpleTestCase

from limes import scope


class ReservedTest(SimpleTestCase):
    def test_reserved_and_public(self):
        for bad in ('10.0.0.1', '127.0.0.1', '169.254.1.1', '100.64.0.1', '224.0.0.1', '0.0.0.0',
                    '::1', 'fe80::1', '64:ff9b::a00:1', '2002:a00:1::', '::ffff:10.0.0.1', 'nonsense', ''):
            self.assertTrue(scope.is_reserved_ip(bad), bad)
        for ok in ('8.8.8.8', '2606:4700:4700::1111', '::ffff:8.8.8.8'):
            self.assertFalse(scope.is_reserved_ip(ok), ok)

    def test_parse_ip_collapses_mapped(self):
        self.assertEqual(str(scope.parse_ip('::ffff:8.8.8.8')), '8.8.8.8')
        self.assertIsNone(scope.parse_ip('example.com'))

    def test_reserved_network_overlap(self):
        self.assertTrue(scope.is_reserved_network(ipaddress.ip_network('0.0.0.0/0')))
        self.assertTrue(scope.is_reserved_network(ipaddress.ip_network('2002::/16')))
        self.assertFalse(scope.is_reserved_network(ipaddress.ip_network('8.8.8.0/24')))


class TargetHostTest(SimpleTestCase):
    def test_forms(self):
        cases = {
            'https://App.Example.com:8443/x?y=1': 'app.example.com',
            'app.example.com': 'app.example.com',
            'app.example.com.': 'app.example.com',
            'app.example.com:80': 'app.example.com',
            '10.0.0.1': '10.0.0.1',
            'http://[::ffff:10.0.0.1]/': '::ffff:10.0.0.1',
            '[2606:4700::1]:443': '2606:4700::1',
        }
        for raw, host in cases.items():
            self.assertEqual(scope.target_host(raw), host, raw)

    def test_empty_or_broken(self):
        for raw in ('', '   ', None, 'http://[::1'):
            self.assertIsNone(scope.target_host(raw), raw)
```

- [ ] **Step 2: Run, confirm fail** — `... manage.py test tests.core.test_scope` → `ImportError: cannot import name 'scope'`.

- [ ] **Step 3: Implement** `web/limes/scope.py`:
```python
"""Scope guard for every stage that sends traffic. Fails closed.

NOTE: checks the IPs recorded by the latest resolution; a tool resolving later
can get a different answer (DNS rebinding). Upgrade path: pin tools to the
resolved IPs (naabu -host <ip>, httpx host-to-IP pinning).
"""
import ipaddress
from urllib.parse import urlsplit

# Overlap with any of these makes an address/network non-public. is_global alone
# misses NAT64/6to4/Teredo, and is_private on a network only tests "subnet of".
RESERVED_NETWORKS = [ipaddress.ip_network(c) for c in (
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
    '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.168.0.0/16', '198.18.0.0/15',
    '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4', '255.255.255.255/32',
    '::1/128', '::/128', 'fc00::/7', 'fe80::/10', 'ff00::/8', '2001:db8::/32', '::ffff:0:0/96',
    '64:ff9b::/96', '64:ff9b:1::/48', '2002::/16', '2001::/23', '100::/64', '5f00::/16',
)]


def parse_ip(value):
    """ip_address for value, IPv4-mapped IPv6 collapsed to IPv4; None if not an IP."""
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip


def is_reserved_ip(value):
    """True unless value is a public unicast address (unparseable counts as reserved)."""
    ip = value if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else parse_ip(value)
    if ip is None:
        return True
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return (ip.is_multicast or not ip.is_global
            or any(ip.version == n.version and ip in n for n in RESERVED_NETWORKS))


def is_reserved_network(net):
    return (any(net.version == r.version and net.overlaps(r) for r in RESERVED_NETWORKS)
            or not net.network_address.is_global or not net.broadcast_address.is_global)


def target_host(target):
    """Host of a URL, host:port, [v6]:port or bare host; None when there is none."""
    t = (target or '').strip()
    if not t:
        return None
    if '://' not in t:
        t = '//' + t
    try:
        host = urlsplit(t).hostname
    except ValueError:
        return None
    host = (host or '').rstrip('.').lower()
    return host or None
```

- [ ] **Step 4: Point `api/asset_add.py` at the shared definitions.** Replace the module's `_RESERVED = [...]` block and the two checks:
```python
from limes.scope import is_reserved_ip, is_reserved_network, parse_ip
```
CIDR branch: `if is_reserved_network(net): return _err(f'private/reserved CIDR rejected: {s}')`.
IP branch:
```python
    ip = parse_ip(s)
    if ip is not None:
        if is_reserved_ip(ip):
            return _err(f'private/reserved IP rejected: {s}')
        return _ok('ip', str(ip))
```
Delete the now-unused `import ipaddress` only if nothing else in the file uses it (the CIDR branch still calls `ipaddress.ip_network`: keep it).

- [ ] **Step 5: Run** `tests.core.test_scope tests.core.test_asset_add` → all PASS (asset_add behaviour unchanged).

- [ ] **Step 6: Commit** — `git add web/limes/scope.py web/api/asset_add.py web/tests/core/test_scope.py && git commit -m "Share reserved-range checks in limes.scope"` (body: why — one definition for manual add and the stage guard).

---

### Task 2: Guard levels `may_contact` / `may_attack`

**Files:**
- Modify: `web/limes/scope.py`
- Test: `web/tests/core/test_scope.py` (add `GuardTest`)

**Interfaces:**
- Consumes: Task 1 helpers; `startScan.models.Asset` (`project`, `kind`, `value`, `scope_tier`, `active_authorized`, `ip_addresses` M2M of `IpAddress(address)`, property `is_active_scan_allowed`).
- Produces: `may_contact(project, targets) -> (list[str], list[tuple[str, str]])`; `may_attack(project, targets, allow_co_brand=True) -> (allowed, refused)`. `allowed` preserves input order and original strings.

- [ ] **Step 1: Write failing tests** (append to `test_scope.py`):
```python
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from dashboard.models import Project
from startScan.models import Asset, IpAddress


class GuardTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.other = Project.objects.create(name='o', slug='o', insert_date=timezone.now())

    def host(self, value, tier='owned_host', ips=(), authorized=False, project=None):
        a = Asset.objects.create(project=project or self.p, kind='hostname', value=value,
                                 scope_tier=tier, active_authorized=authorized)
        for ip in ips:
            a.ip_addresses.add(IpAddress.objects.create(address=ip))
        return a

    def test_contact_requires_resolution_and_public_ips(self):
        self.host('ok.x.com', ips=['8.8.8.8'])
        self.host('mixed.x.com', ips=['8.8.8.8', '10.0.0.5'])
        self.host('10.0.0.1.nip.io', ips=['10.0.0.1'])
        self.host('unresolved.x.com')
        allowed, refused = scope.may_contact(self.p, [
            'https://ok.x.com/a', 'mixed.x.com', '10.0.0.1.nip.io', 'unresolved.x.com',
            'unknown.x.com', '8.8.4.4', 'http://[::ffff:10.0.0.1]/'])
        self.assertEqual(allowed, ['https://ok.x.com/a', '8.8.4.4'])
        reasons = dict(refused)
        self.assertIn('10.0.0.5', reasons['mixed.x.com'])
        self.assertIn('not resolved', reasons['unresolved.x.com'])
        self.assertIn('not resolved', reasons['unknown.x.com'])

    def test_attack_requires_scannable_tier(self):
        for value, tier, auth in (('own.x.com', 'owned_host', False), ('dep.x.com', 'dependency', False),
                                  ('cand.x.com', 'candidate', False), ('rej.x.com', 'rejected', False),
                                  ('cb.x.com', 'co_brand', False), ('cba.x.com', 'co_brand', True)):
            self.host(value, tier=tier, ips=['8.8.8.8'], authorized=auth)
        targets = ['own.x.com', 'dep.x.com', 'cand.x.com', 'rej.x.com', 'cb.x.com', 'cba.x.com', '1.1.1.1']
        allowed, _ = scope.may_attack(self.p, targets)
        self.assertEqual(allowed, ['own.x.com', 'cba.x.com'])
        allowed, _ = scope.may_attack(self.p, targets, allow_co_brand=False)
        self.assertEqual(allowed, ['own.x.com'])

    def test_project_isolation(self):
        self.host('theirs.x.com', ips=['8.8.8.8'], project=self.other)
        self.assertEqual(scope.may_attack(self.p, ['theirs.x.com'])[0], [])

    def test_fails_closed(self):
        self.host('ok.x.com', ips=['8.8.8.8'])
        self.assertEqual(scope.may_attack(None, ['ok.x.com'])[0], [])
        with mock.patch('limes.scope._assets_by_value', side_effect=RuntimeError('db down')):
            allowed, refused = scope.may_contact(self.p, ['ok.x.com'])
        self.assertEqual(allowed, [])
        self.assertIn('scope check failed', refused[0][1])
```

- [ ] **Step 2: Run, confirm fail** — `AttributeError: module 'limes.scope' has no attribute 'may_contact'`.

- [ ] **Step 3: Implement** (append to `scope.py`):
```python
def _assets_by_value(project, hosts):
    from startScan.models import Asset
    by_value = {}
    # NOTE: one IN query per call; fine for tens of thousands of targets.
    for a in Asset.objects.filter(project=project, value__in=hosts).prefetch_related('ip_addresses'):
        by_value.setdefault(a.value, []).append(a)
    return by_value


def _refusal(host, assets, attack, allow_co_brand):
    if not host:
        return 'no host'
    ip = parse_ip(host)
    if ip is not None:
        ips = {str(ip)}
    else:
        ips = {i.address for a in assets for i in a.ip_addresses.all() if i.address}
        if not ips:
            return 'not resolved'
    bad = sorted(i for i in ips if is_reserved_ip(i))
    if bad:
        return 'resolves to private/reserved ' + ', '.join(bad)
    if not attack:
        return None
    if not assets:
        return 'not in inventory'
    if any(a.is_active_scan_allowed and (allow_co_brand or a.scope_tier != 'co_brand') for a in assets):
        return None
    return 'scope tier ' + '/'.join(sorted({a.scope_tier for a in assets})) + ' is not actively scannable'


def _check(project, targets, attack, allow_co_brand):
    targets = list(targets)
    if project is None:
        return [], [(t, 'no project') for t in targets]
    allowed, refused = [], []
    try:
        hosts = {t: target_host(t) for t in targets}
        assets = _assets_by_value(project, {h for h in hosts.values() if h})
        for t in targets:
            h = hosts[t]
            p = parse_ip(h) if h else None
            reason = _refusal(h, assets.get(str(p) if p else h, []), attack, allow_co_brand)
            if reason:
                refused.append((t, reason))
            else:
                allowed.append(t)
    except Exception as e:  # fail closed on any lookup error
        return [], [(t, f'scope check failed: {e}') for t in targets]
    return allowed, refused


def may_contact(project, targets):
    """Allowed to send any packet: every resolved IP is public."""
    return _check(project, targets, attack=False, allow_co_brand=True)


def may_attack(project, targets, allow_co_brand=True):
    """may_contact plus an actively scannable scope tier."""
    return _check(project, targets, attack=True, allow_co_brand=allow_co_brand)
```
Note `'1.1.1.1'` in `test_attack_requires_scannable_tier` has no asset → `not in inventory` → refused (fail closed).

- [ ] **Step 4: Run** `tests.core.test_scope` → PASS.

- [ ] **Step 5: Commit** — `git commit -m "Add fail-closed scope guard levels"`.

---

### Task 3: `dependency` tier + IP ownership on upsert

**Files:**
- Modify: `web/startScan/asset_models.py` (`SCOPE_TIERS`)
- Create (generated): `web/startScan/migrations/0011_asset_dependency_tier.py`
- Modify: `web/limes/tasks/inventory.py` (`upsert_ip_asset`, new `owned_ip_space`; delete unused `is_active_scan_allowed_for`)
- Modify: `web/startScan/templates/startScan/assets.html` (filter option), `web/static/custom/asset.js` (Confirm/Reject also for `dependency`)
- Test: `web/tests/core/test_ip_ownership.py` (create)

**Interfaces:**
- Consumes: `scope.parse_ip`, `scope.is_reserved_ip`.
- Produces: `inventory.owned_ip_space(project) -> list[ip_network]`; `upsert_ip_asset(project, address, source='probe', evidence='')` unchanged signature, new tier rule.

- [ ] **Step 1: Write failing tests** (`test_ip_ownership.py`):
```python
from django.test import TestCase
from django.utils import timezone

from dashboard.models import Project
from limes.tasks import inventory
from startScan.models import Asset


class IpOwnershipTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        Asset.objects.create(project=self.p, kind='cidr', value='203.0.114.0/24', scope_tier='owned_host')
        Asset.objects.create(project=self.p, kind='cidr', value='198.51.99.0/24', scope_tier='candidate')

    def tier(self, address):
        return inventory.upsert_ip_asset(self.p, address, source='dns', evidence='host:a').scope_tier

    def test_new_ip_inside_owned_cidr_is_owned(self):
        self.assertEqual(self.tier('203.0.114.7'), 'owned_host')

    def test_new_ip_elsewhere_is_dependency(self):
        self.assertEqual(self.tier('104.16.1.1'), 'dependency')
        self.assertEqual(self.tier('198.51.99.4'), 'dependency')  # candidate CIDR proves nothing
        self.assertEqual(self.tier('10.1.2.3'), 'dependency')

    def test_existing_tier_never_changes(self):
        Asset.objects.create(project=self.p, kind='ip', value='8.8.8.8', scope_tier='owned_host')
        Asset.objects.create(project=self.p, kind='ip', value='203.0.114.9', scope_tier='dependency')
        self.assertEqual(self.tier('8.8.8.8'), 'owned_host')
        self.assertEqual(self.tier('203.0.114.9'), 'dependency')

    def test_dependency_is_not_scannable(self):
        a = Asset.objects.create(project=self.p, kind='ip', value='9.9.9.9', scope_tier='dependency')
        self.assertFalse(a.is_active_scan_allowed)
```

- [ ] **Step 2: Run, confirm fail** — `'owned_host' != 'dependency'` (today every new IP is `owned_host`).

- [ ] **Step 3: Tier.** In `startScan/asset_models.py`:
```python
SCOPE_TIERS = [('owned_root', 'owned_root'), ('owned_host', 'owned_host'),
               ('co_brand', 'co_brand'), ('candidate', 'candidate'), ('rejected', 'rejected'),
               ('dependency', 'dependency')]  # infrastructure we rely on, never scanned by IP
```
Generate: `manage.py makemigrations startScan -n asset_dependency_tier` → `0011_asset_dependency_tier.py` (AlterField only).

- [ ] **Step 4: Ownership rule** in `limes/tasks/inventory.py` (add `import ipaddress` and `from limes import scope`):
```python
def owned_ip_space(project):
    """Networks a person (or an owned root's import) declared ours: owned ip/cidr assets."""
    nets = []
    for value in Asset.objects.filter(project=project, kind__in=('ip', 'cidr'),
                                      scope_tier__in=('owned_root', 'owned_host')).values_list('value', flat=True):
        try:
            nets.append(ipaddress.ip_network(value, strict=False))
        except ValueError:
            continue
    return nets


def _new_ip_tier(project, address):
    ip = scope.parse_ip(address)
    if ip is None or scope.is_reserved_ip(ip):
        return 'dependency'
    if any(ip.version == n.version and ip in n for n in owned_ip_space(project)):
        return 'owned_host'
    return 'dependency'


def upsert_ip_asset(project, address, source='probe', evidence=''):
    if not address:
        return None
    asset, created = Asset.objects.get_or_create(
        project=project, kind='ip', value=address,
        defaults={'scope_tier': 'dependency'})
    if created:
        # DNS/probe evidence never promotes: owned only inside declared owned space.
        asset.scope_tier = _new_ip_tier(project, address)
    _append_source(asset, source, evidence)
    asset.save()
    asset.mark_missing_or_seen(True)
    return asset
```
Delete `is_active_scan_allowed_for` (no callers; superseded by `scope.may_attack`) — confirm first with `grep -rn is_active_scan_allowed_for web/`.

- [ ] **Step 5: UI.** `assets.html` scope `<select>`: add `<option>dependency</option>` after `rejected`. `asset.js` `asset_actions`: change `if (row.scope_tier === 'candidate')` to `if (row.scope_tier === 'candidate' || row.scope_tier === 'dependency')` so a person can confirm a dependency IP as owned (spec: "or someone confirms it").

- [ ] **Step 6: Run** `tests.core.test_ip_ownership tests.core.test_inventory_writes tests.core.test_asset_api` → PASS; `makemigrations --check --dry-run` → No changes detected.

- [ ] **Step 7: Commit** — `git commit -m "Record resolved IPs as dependencies unless inside owned space"`.

---

### Task 4: Demote previously auto-owned IPs

**Files:**
- Create: `web/startScan/migrations/0012_demote_auto_owned_ips.py` (RunPython; `makemigrations startScan --empty -n demote_auto_owned_ips` then fill)
- Test: `web/tests/core/test_demote_ips.py` (create)

**Interfaces:**
- Produces: `demote_auto_owned_ips(apps, schema_editor)` in that migration module.

- [ ] **Step 1: Write failing test:**
```python
import importlib

from django.apps import apps as django_apps
from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone

from dashboard.models import Project
from startScan.models import Asset

migration = importlib.import_module('startScan.migrations.0012_demote_auto_owned_ips')


class DemoteAutoOwnedIpsTest(TestCase):
    def test_only_machine_created_undecided_ips_outside_owned_space(self):
        p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        u = User.objects.create_user('u')
        Asset.objects.create(project=p, kind='cidr', value='203.0.114.0/24', scope_tier='owned_host')
        mk = lambda v, **kw: Asset.objects.create(project=p, kind='ip', value=v, scope_tier='owned_host', **kw)
        probe = mk('104.16.1.1', sources=[{'source': 'probe', 'evidence': 'host:a'}])
        backfill = mk('104.16.1.2')                                            # A0 back-fill: no sources
        manual = mk('104.16.1.3', added_by=u)
        reasoned = mk('104.16.1.4', decision_reason='our colo')
        in_cidr = mk('203.0.114.5', sources=[{'source': 'probe', 'evidence': 'host:b'}])
        other_src = mk('104.16.1.6', sources=[{'source': 'manual', 'evidence': 'x'}])
        migration.demote_auto_owned_ips(django_apps, None)
        tiers = {a.value: a.scope_tier for a in Asset.objects.filter(kind='ip')}
        self.assertEqual(tiers, {'104.16.1.1': 'dependency', '104.16.1.2': 'dependency',
                                 '104.16.1.3': 'owned_host', '104.16.1.4': 'owned_host',
                                 '203.0.114.5': 'owned_host', '104.16.1.6': 'owned_host'})
```

- [ ] **Step 2: Run, confirm fail** — `ModuleNotFoundError ... 0012_demote_auto_owned_ips`.

- [ ] **Step 3: Implement** the migration:
```python
import ipaddress

from django.db import migrations

AUTO_SOURCES = {'probe', 'dns'}


def demote_auto_owned_ips(apps, schema_editor):
    """IPs the old pipeline auto-owned (probe/dns evidence or A0 back-fill, no human decision)
    become dependencies unless they sit inside owned space a person declared."""
    Asset = apps.get_model('startScan', 'Asset')
    owned = Asset.objects.filter(kind__in=('ip', 'cidr'), scope_tier__in=('owned_root', 'owned_host'))
    declared = {}
    for a in owned.exclude(kind='ip', added_by__isnull=True, decision_reason=''):
        try:
            declared.setdefault(a.project_id, []).append(ipaddress.ip_network(a.value, strict=False))
        except ValueError:
            continue
    for a in owned.filter(kind='ip', added_by__isnull=True, decision_reason='').iterator():
        if any((s or {}).get('source') not in AUTO_SOURCES for s in (a.sources or [])):
            continue
        try:
            ip = ipaddress.ip_address(a.value)
        except ValueError:
            continue
        if any(ip.version == n.version and ip in n for n in declared.get(a.project_id, [])):
            continue
        a.scope_tier = 'dependency'
        a.save(update_fields=['scope_tier'])


class Migration(migrations.Migration):
    dependencies = [('startScan', '0011_asset_dependency_tier')]
    operations = [migrations.RunPython(demote_auto_owned_ips, migrations.RunPython.noop)]
```

- [ ] **Step 4: Run** the test + full suite (test DB builds through the new migration) → PASS.

- [ ] **Step 5: Commit** — `git commit -m "Demote auto-owned IPs to dependencies"`; body must state the operator-visible change: shared CDN/SaaS IPs that were port-scanned stop being scanned after upgrade.

---

### Task 5: `limes/pipeline/dnsx.py` — argv + parser

**Files:**
- Create: `web/limes/pipeline/dnsx.py`
- Create: `web/tests/core/fixtures/dnsx_sample.jsonl`
- Test: `web/tests/core/test_dnsx.py` (create)

**Interfaces:**
- Produces: `build_argv(hosts_file: str, output_file: str) -> list[str]`; `parse(lines: Iterable[str]) -> dict[str, {'a': list[str], 'aaaa': list[str], 'cname': list[str]}]`.

- [ ] **Step 1: Fixture** `dnsx_sample.jsonl` (one JSON object per line, exactly as dnsx `-json` emits):
```
{"host":"App.Example.com","a":["93.184.216.34","93.184.216.34"],"aaaa":["2606:2800:220:1::1"],"cname":["Edge.CDN.net."]}
{"host":"alias.example.com","cname":["app.example.com"]}
not json at all
{"host":"bad.example.com","a":["not-an-ip", 7]}
{"a":["1.2.3.4"]}
```

- [ ] **Step 2: Failing tests** (`test_dnsx.py`):
```python
import os

from django.test import SimpleTestCase

from limes.pipeline import dnsx

FIXTURE = os.path.join(os.path.dirname(__file__), 'fixtures', 'dnsx_sample.jsonl')


class DnsxTest(SimpleTestCase):
    def test_argv_is_a_list_with_files(self):
        argv = dnsx.build_argv('/r/hosts.txt', '/r/out.jsonl')
        self.assertEqual(argv[0], 'dnsx')
        self.assertEqual(argv[argv.index('-l') + 1], '/r/hosts.txt')
        self.assertEqual(argv[argv.index('-o') + 1], '/r/out.jsonl')
        for flag in ('-a', '-aaaa', '-cname', '-resp', '-json', '-silent'):
            self.assertIn(flag, argv)

    def test_parse_fixture(self):
        with open(FIXTURE) as f:
            out = dnsx.parse(f)
        self.assertEqual(out['app.example.com'], {'a': ['93.184.216.34'], 'aaaa': ['2606:2800:220:1::1'],
                                                  'cname': ['edge.cdn.net']})
        self.assertEqual(out['alias.example.com'], {'a': [], 'aaaa': [], 'cname': ['app.example.com']})
        self.assertEqual(out['bad.example.com'], {'a': [], 'aaaa': [], 'cname': []})
        self.assertEqual(set(out), {'app.example.com', 'alias.example.com', 'bad.example.com'})
```

- [ ] **Step 3: Run, confirm fail** — `ImportError: cannot import name 'dnsx'`.

- [ ] **Step 4: Implement** `web/limes/pipeline/dnsx.py`:
```python
"""ProjectDiscovery dnsx integration: resolve A/AAAA/CNAME for a host list."""
import ipaddress
import json

from startScan.inventory_migrate import normalize_host


def build_argv(hosts_file, output_file):
    return ['dnsx', '-l', hosts_file, '-a', '-aaaa', '-cname', '-resp', '-json', '-silent', '-o', output_file]


def _valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def parse(lines):
    out = {}
    for line in lines:
        try:
            rec = json.loads(line)
        except (TypeError, ValueError):
            continue
        if not isinstance(rec, dict):
            continue
        host = normalize_host(rec.get('host') if isinstance(rec.get('host'), str) else '')
        if not host:
            continue
        entry = out.setdefault(host, {'a': [], 'aaaa': [], 'cname': []})
        for key in ('a', 'aaaa'):
            for v in rec.get(key) or []:
                if isinstance(v, str) and _valid_ip(v) and v not in entry[key]:
                    entry[key].append(v)
        for v in rec.get('cname') or []:
            c = normalize_host(v) if isinstance(v, str) else ''
            if c and c not in entry['cname']:
                entry['cname'].append(c)
    return out
```

- [ ] **Step 5: Run** → PASS. **Step 6: Commit** — `git commit -m "Add dnsx argv builder and parser"`.

---

### Task 6: Resolution inside discovery

**Files:**
- Modify: `web/startScan/asset_models.py` (`last_resolved_at`), generate `0013_asset_last_resolved_at.py`
- Modify: `web/limes/tasks/inventory.py` (`record_resolution`)
- Create: `web/limes/tasks/resolution.py`
- Modify: `web/limes/tasks/stages.py` (`subdomain_discovery`: call before `http_crawl`)
- Test: `web/tests/core/test_resolution.py` (create)

**Interfaces:**
- Consumes: `dnsx.build_argv`, `dnsx.parse`, `inventory.upsert_ip_asset`, `commands.run` (returns object with `return_code`).
- Produces: `inventory.record_resolution(asset, record) -> None`; `resolution.resolve_root(project, root_asset, results_dir, run=commands.run) -> int`.

- [ ] **Step 1: Failing tests** (`test_resolution.py`):
```python
import os
import shutil
import tempfile
from types import SimpleNamespace

from django.test import TestCase
from django.utils import timezone

from dashboard.models import Project
from limes.tasks import resolution
from startScan.models import Asset, IpAddress

FIXTURE = os.path.join(os.path.dirname(__file__), 'fixtures', 'dnsx_sample.jsonl')


class ResolveRootTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.root = Asset.objects.create(project=self.p, kind='root_domain', value='example.com', scope_tier='owned_root')
        self.app = Asset.objects.create(project=self.p, kind='hostname', value='app.example.com',
                                        scope_tier='owned_host', parent=self.root)
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        self.argvs = []

    def fake_run(self, rc=0, write=True):
        def run(argv, **kw):
            self.argvs.append(argv)
            with open(argv[argv.index('-l') + 1]) as f:
                self.hosts = f.read().split()
            if write:
                shutil.copy(FIXTURE, argv[argv.index('-o') + 1])
            return SimpleNamespace(return_code=rc)
        return run

    def test_records_ips_as_dependencies_and_cname(self):
        n = resolution.resolve_root(self.p, self.root, self.dir, run=self.fake_run())
        self.assertEqual(n, 1)                                   # only app.example.com is in inventory
        self.assertEqual(sorted(self.hosts), ['app.example.com', 'example.com'])
        self.app.refresh_from_db()
        self.assertEqual(self.app.cname, 'edge.cdn.net')
        self.assertIsNotNone(self.app.last_resolved_at)
        self.assertEqual(sorted(self.app.ip_addresses.values_list('address', flat=True)),
                         ['2606:2800:220:1::1', '93.184.216.34'])
        ip = Asset.objects.get(project=self.p, kind='ip', value='93.184.216.34')
        self.assertEqual(ip.scope_tier, 'dependency')
        self.assertEqual(ip.sources[0]['source'], 'dns')

    def test_failed_run_records_nothing_and_ignores_stale_output(self):
        resolution.resolve_root(self.p, self.root, self.dir, run=self.fake_run())
        Asset.objects.filter(kind='ip').delete()
        n = resolution.resolve_root(self.p, self.root, self.dir, run=self.fake_run(rc=1, write=False))
        self.assertEqual(n, 0)
        self.assertFalse(Asset.objects.filter(kind='ip').exists())

    def test_runner_exception_is_contained(self):
        def boom(argv, **kw):
            raise OSError('dnsx missing')
        self.assertEqual(resolution.resolve_root(self.p, self.root, self.dir, run=boom), 0)

    def test_duplicate_legacy_ip_rows_do_not_crash(self):
        IpAddress.objects.create(address='93.184.216.34')
        IpAddress.objects.create(address='93.184.216.34')
        self.assertEqual(resolution.resolve_root(self.p, self.root, self.dir, run=self.fake_run()), 1)
```

- [ ] **Step 2: Run, confirm fail** — `ImportError: cannot import name 'resolution'`.

- [ ] **Step 3: Field.** `Asset.last_resolved_at = models.DateTimeField(null=True, blank=True)` (next to `last_seen`); `makemigrations startScan -n asset_last_resolved_at` → `0013`.

- [ ] **Step 4: `inventory.record_resolution`:**
```python
def record_resolution(asset, record):
    """Write one host's dnsx answer: CNAME, IP assets (via upsert_ip_asset), host->IP links."""
    from startScan.models import IpAddress
    if record.get('cname'):
        asset.cname = record['cname'][0]
    for address in list(record.get('a', [])) + list(record.get('aaaa', [])):
        upsert_ip_asset(asset.project, address, source='dns', evidence=f'host:{asset.value}')
        # address is not unique on the legacy table: reuse the oldest row
        ip = IpAddress.objects.filter(address=address).order_by('id').first() or IpAddress.objects.create(address=address)
        asset.ip_addresses.add(ip)
    asset.last_resolved_at = timezone.now()
    asset.save(update_fields=['cname', 'last_resolved_at'])
```

- [ ] **Step 5: `web/limes/tasks/resolution.py`:**
```python
"""DNS resolution of a root's inventory with dnsx (runs inside discovery, before any probe)."""
import logging
import os

from limes import commands
from limes.pipeline import dnsx
from limes.tasks import inventory
from startScan.models import Asset

logger = logging.getLogger(__name__)


def resolve_root(project, root_asset, results_dir, run=commands.run):
    """Resolve the root and its hostname assets; returns how many hosts were recorded.
    Best-effort: failures are logged and leave previous resolutions untouched."""
    if not project or not root_asset:
        return 0
    # NOTE: holds one root's hostnames in memory (tens of thousands is fine).
    assets = {root_asset.value: root_asset}
    for a in Asset.objects.filter(project=project, kind='hostname', parent=root_asset).iterator(chunk_size=2000):
        assets[a.value] = a
    hosts_file = os.path.join(results_dir, 'resolve_hosts.txt')
    out_file = os.path.join(results_dir, 'dnsx.jsonl')
    if os.path.exists(out_file):
        os.remove(out_file)  # never re-read a previous run's answers
    with open(hosts_file, 'w') as f:
        f.write('\n'.join(assets) + '\n')
    try:
        res = run(dnsx.build_argv(hosts_file, out_file))
    except Exception:
        logger.exception('dnsx failed to run')
        return 0
    if res is None or res.return_code != 0:
        logger.warning(f'dnsx exited with {getattr(res, "return_code", None)}')
    if not os.path.isfile(out_file):
        return 0
    with open(out_file) as f:
        records = dnsx.parse(f)
    count = 0
    for name, record in records.items():
        asset = assets.get(name)
        if asset is not None:
            inventory.record_resolution(asset, record)
            count += 1
    return count
```

- [ ] **Step 6: Run** `tests.core.test_resolution` → PASS.

- [ ] **Step 7: Wire into discovery** (`limes/tasks/stages.py`, `subdomain_discovery`). Add imports at the top: `from limes.tasks import resolution` and `from startScan.asset_models import ScanRun`. Replace
```python
	# Bulk crawl subdomains
	if enable_http_crawl:
```
with
```python
	# Resolve before any probe: the contact guard refuses unresolved hosts.
	run = ScanRun.objects.filter(pk=ctx.get('scan_run_id')).select_related('project', 'root_asset').first()
	if run:
		resolution.resolve_root(run.project, run.root_asset, self.results_dir)

	# Bulk crawl subdomains
	if enable_http_crawl:
```
Keep the two blocks adjacent (Review Focus 1).

- [ ] **Step 8: Run** the full suite; `makemigrations --check --dry-run` clean. **Step 9: Commit** — `git commit -m "Resolve discovered hosts with dnsx before probing"`.

---

### Task 7: Guard every traffic-sending stage

**Files:**
- Modify: `web/limes/tasks/stages.py` (`_in_scope` helper; `http_crawl`, `screenshot`, `port_scan`, `nmap`, `fetch_url`, `vulnerability_scan`)
- Test: `web/tests/core/test_stage_scope.py` (create)

**Interfaces:**
- Consumes: `scope.may_contact`, `scope.may_attack`.
- Produces: `stages._in_scope(task, targets, level, allow_co_brand=True) -> list[str]` (`level` is `'contact'` or `'attack'`).

- [ ] **Step 1: Failing tests** (`test_stage_scope.py`) — stages run for real through `LimesTask.__call__` (pattern from `test_scan_mode.py`), tools mocked:
```python
import os
import tempfile
from types import SimpleNamespace
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from dashboard.models import Project
from limes.celery_custom_task import LimesTask
from limes.tasks import stages
from scanEngine.models import EngineType
from startScan.models import Asset, IpAddress, ScanHistory
from targetApp.models import Domain


class StageScopeTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.domain = Domain.objects.create(name='x.com', project=self.p, insert_date=timezone.now())
        eng = EngineType.objects.create(engine_name='e', yaml_configuration='{}')
        self.dir = tempfile.mkdtemp()
        self.scan = ScanHistory.objects.create(scan_type=eng, domain=self.domain,
                                               start_scan_date=timezone.now(), results_dir=self.dir)
        self.ctx = {'scan_history_id': self.scan.id, 'results_dir': self.dir, 'track': False}
        for value, tier, ip, auth in (('own.x.com', 'owned_host', '8.8.8.8', False),
                                      ('priv.x.com', 'owned_host', '10.0.0.9', False),
                                      ('dep.x.com', 'dependency', '8.8.4.4', False),
                                      ('cb.x.com', 'co_brand', '1.1.1.1', True)):
            a = Asset.objects.create(project=self.p, kind='hostname', value=value, scope_tier=tier, active_authorized=auth)
            a.ip_addresses.add(IpAddress.objects.create(address=ip))
        p = mock.patch.object(LimesTask, 'notify')
        p.start()
        self.addCleanup(p.stop)

    def read(self, name):
        path = os.path.join(self.dir, name)
        return open(path).read().split() if os.path.exists(path) else None

    def test_port_scan_drops_refused_and_co_brand(self):
        with mock.patch.object(stages, 'stream_command', return_value=iter([])) as sc:
            stages.port_scan(hosts=['own.x.com', 'priv.x.com', 'dep.x.com', 'cb.x.com'], ctx=dict(self.ctx))
        self.assertEqual(self.read('input_subdomains_port_scan.txt'), ['own.x.com'])
        sc.assert_called_once()

    def test_port_scan_all_refused_never_falls_back(self):
        with mock.patch.object(stages, 'stream_command') as sc, \
                mock.patch.object(stages, 'get_subdomains') as gs:
            stages.port_scan(hosts=['priv.x.com', 'dep.x.com'], ctx=dict(self.ctx))
        sc.assert_not_called()
        gs.assert_not_called()

    def test_nmap_refuses_out_of_scope_host(self):
        with mock.patch.object(stages, 'run_command') as rc:
            stages.nmap(host='cb.x.com', ports=[443], ctx=dict(self.ctx))
            stages.nmap(host=None, input_file='/tmp/whatever', ports=[443], ctx=dict(self.ctx))
        rc.assert_not_called()

    def test_http_crawl_contact_level(self):
        # run_command is mocked too: http_crawl ends with `rm <input file>`
        with mock.patch.object(stages, 'stream_command', return_value=iter([])) as sc, \
                mock.patch.object(stages, 'run_command'):
            stages.http_crawl(urls=['own.x.com', 'priv.x.com', 'dep.x.com', 'cb.x.com'], ctx=dict(self.ctx))
        self.assertEqual(sorted(self.read('httpx_input.txt')), ['cb.x.com', 'dep.x.com', 'own.x.com'])
        sc.assert_called_once()

    def test_vulnerability_scan_attack_level(self):
        urls = ['https://own.x.com/', 'https://priv.x.com/', 'https://dep.x.com/', 'https://cb.x.com/']
        with mock.patch.object(stages, 'get_http_urls', return_value=urls), \
                mock.patch.object(stages.commands, 'run', return_value=SimpleNamespace(return_code=0, output='')) as run:
            stages.vulnerability_scan(ctx=dict(self.ctx))
        self.assertEqual(self.read('assay_targets.txt'), ['https://own.x.com/', 'https://cb.x.com/'])
        run.assert_called_once()

    def test_screenshot_contact_level(self):
        urls = ['https://own.x.com/', 'https://priv.x.com/']
        with mock.patch.object(stages, 'get_http_urls', return_value=urls), \
                mock.patch.object(stages.commands, 'run', return_value=SimpleNamespace(return_code=0, output='')):
            stages.screenshot(ctx=dict(self.ctx))
        self.assertEqual(self.read('endpoints_alive.txt'), ['https://own.x.com/'])

    def test_fetch_url_attack_level(self):
        with mock.patch.object(stages.commands, 'run', return_value=SimpleNamespace(return_code=0, output='')):
            stages.fetch_url(urls=['https://own.x.com/', 'https://dep.x.com/'], ctx=dict(self.ctx))
        self.assertEqual(self.read('input_endpoints_fetch_url.txt'), ['https://own.x.com/'])
```
(Later code in `fetch_url`/`screenshot` may fail on the empty mocked tool output; `LimesTask.__call__` records the failure. The assertions only concern the input files, which are written before the tools run.)

- [ ] **Step 2: Run, confirm fail** — refused hosts appear in the input files.

- [ ] **Step 3: Helper** (top of `stages.py`, after imports; add `from limes import scope`):
```python
def _in_scope(task, targets, level, allow_co_brand=True):
	"""Drop targets the scope guard refuses (fails closed) and report them."""
	project = task.domain.project if task.domain else None
	if level == 'contact':
		allowed, refused = scope.may_contact(project, targets)
	else:
		allowed, refused = scope.may_attack(project, targets, allow_co_brand=allow_co_brand)
	for target, reason in refused:
		logger.warning(f'Scope: refusing {target}: {reason}')
	if refused:
		task.notify(fields={'Refused (scope)': len(refused)})
	return allowed
```

- [ ] **Step 4: `port_scan`** — replace the `if hosts: ... else: hosts = get_subdomains(...)` block with:
```python
	if not hosts:
		hosts = get_subdomains(exclude_subdomains=exclude_subdomains, ctx=ctx)
	hosts = _in_scope(self, hosts, 'attack', allow_co_brand=False)
	if not hosts:
		logger.warning('Port scan: no in-scope hosts, skipping')
		return {}
	with open(input_file, 'w') as f:
		f.write('\n'.join(hosts))
```
`port_scan` must not call `get_subdomains` when the caller passed hosts that were all refused — the `if not hosts` fallback runs before filtering, so that holds.

- [ ] **Step 5: `nmap`** — first lines of the body:
```python
	if not host or not _in_scope(self, [host], 'attack', allow_co_brand=False):
		logger.warning(f'nmap: {host or input_file} refused by scope guard')
		return
```

- [ ] **Step 6: `http_crawl`** — after the `exclude_urls_by_patterns` filter and before `if not urls: return`:
```python
	urls = _in_scope(self, urls, 'contact')
	if urls:
		with open(input_path, 'w') as f:
			f.write('\n'.join(urls))
```
(This also fixes the existing bug where excluded URLs stayed in the file written earlier.)

- [ ] **Step 7: `screenshot`** — capture the helper's return value and guard it:
```python
	urls = get_http_urls(
		is_alive=enable_http_crawl,
		strict=strict,
		write_filepath=alive_endpoints_file,
		get_only_default_urls=True,
		ctx=ctx
	) or []
	urls = _in_scope(self, urls, 'contact')
	if not urls:
		logger.warning('Screenshot: no in-scope URLs, skipping')
		return []
	with open(alive_endpoints_file, 'w') as f:
		f.write('\n'.join(urls))
```

- [ ] **Step 8: `fetch_url`** — right after the URL-derivation `if urls: ... else: urls = get_http_urls(...)` block, before `host = ...`:
```python
	urls = _in_scope(self, urls, 'attack')
	if not urls:
		logger.warning('Fetch URL: no in-scope URLs, skipping')
		return []
	with open(input_path, 'w') as f:
		f.write('\n'.join(urls))
```

- [ ] **Step 9: `vulnerability_scan`** — `target_urls = _in_scope(self, get_http_urls(is_alive=True, ctx=ctx) or [], 'attack')` (the existing empty check then returns 0).

- [ ] **Step 10: Run** `tests.core.test_stage_scope` → PASS; full suite green.

- [ ] **Step 11: Every traffic-sending call is guarded** — `grep -n "commands.run(\|stream_command(\|run_command(" web/limes/tasks/stages.py` and confirm each sits in a guarded stage (or is `subdomain_discovery`'s passive tools / the file housekeeping `rm`/`cat`/`sort`, or `code_audit`, which sends nothing).

- [ ] **Step 12: Commit** — `git commit -m "Guard every traffic-sending stage with the scope check"`.
