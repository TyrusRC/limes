# Phase 0B: Default Pipeline + Scan Identity — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the pick-any-tools scan model with one fixed, efficient pipeline — amass v5 + subfinder → dnsx → naabu + nmap → httpx → katana + gau → assay (DAST) → mantis (SAST on crawled code) — remove ~14 overlapping tools, and give every target a scan identity (custom User-Agent + headers) carried safely through the tools.

**Architecture:** Scan engines stop choosing tools and become profiles (`quick`, `normal`, `thorough`, `passive`) that only tune depth/limits/timeouts. Each stage is a task that shells out through phase 0A's argument-list runner (no `shell=True`). assay and mantis are external programs invoked as subprocesses with `--json` / the `mantis.audit()` API; their findings map onto the existing `Vulnerability` model. assay runs nuclei internally, so the standalone nuclei/dalfox/crlfuzz/wafw00f tasks are deleted. A per-project scan identity (reusing `Domain.request_headers`) with encrypted secret headers is written into every tool that sends HTTP traffic, via 0600 temp files for secrets.

**Tech Stack:** Python 3.10, Django 3.2, Celery 5.4, the phase 0A runner (`limes.commands`), assay (Go, `/home/kali/project/trc/assay`), mantis (`mantis-sast`, `/home/kali/project/trc/mantis`), amass v5, subfinder, dnsx, naabu, nmap, httpx, katana, gau, opengrep.

**Spec:** `docs/superpowers/specs/2026-10-07-phase0-performance-pipeline-design.md` (this plan implements R13 and the completion of S1, plus the scan-identity section; R1-R12/S2/S3 are plan 0A). Roadmap: `docs/superpowers/specs/2026-10-07-asm-platform-roadmap-design.md`.

**Depends on:** plan 0A merged (this plan uses `limes.commands.run`/`stream`, the three-queue routing, `celery_routing.TASK_PLAN`, and the absence of in-task joins). Branch from the 0A head.

## Global Constraints

- `web/limes/tasks.py`, `common_func.py`, `definitions.py` use TABS. New modules use 4 spaces.
- Pinned tool versions (build args in `web/Dockerfile`): Go `go1.27.1`; amass `v5.1.1` (`CGO_ENABLED=0 go install -v github.com/owasp-amass/amass/v5/cmd/amass@v5.1.1`); subfinder `v2.16.0`; dnsx `v1.3.1`; naabu `v2.6.1`; httpx `v1.12.0`; katana `v1.8.0`; nuclei `v3.11.1`; gau `v2.2.4`; opengrep `v1.30.1` (asset `opengrep_manylinux_x86` / `_aarch64`, chmod +x to `/usr/local/bin/opengrep`); mantis via `pipx install mantis-sast` or `pip install mantis-sast`.
- assay is built from source at `/home/kali/project/trc/assay` and the `assay` binary copied into the image; it is invoked as a subprocess, never `assay serve`.
- Destructive/heavy assay flags are NEVER in a built argv on scheduled scans: `--h2-reset`, `--h2-continuation`, `--h2-madeyoureset`, `--redos`, `--mass-assign`, `--proto-pollution-server`, `--rate-limit`.
- Every external tool runs through `limes.commands.run`/`stream` (argument lists; no `shell=True`). No new `shell=True` call sites.
- Scope stays as today: subdomains of the target root only; no ASN/CIDR/WHOIS expansion (that is sub-project 2). amass runs in domain-enumeration mode for the single target domain.
- Scan identity secret header values never appear in the DB `Command` row, `commands.txt`, logs, or tool argv (redacted or passed via 0600 temp file).
- Tests: `web/tests/core/`, run with `make test` (phase 0A harness). Never run `web/tests/test_scan.py`. Docker via `DOCKER_HOST=unix:///var/run/docker.sock`.
- Commit identity TyrusRC (already configured). No AI attribution in commits. Never bypass hooks.

## Review Focus

1. **A target whose scan identity has no User-Agent** (only extra headers): httpx must still get a deterministic UA and `-random-agent` must stay off, or probes become non-reproducible — Task 9 tests identity with headers but no UA.
2. **assay exits non-zero because a finding crossed a fail-on threshold (exit 2) vs a real crash (exit 1)** — the DAST task must treat exit 2 as success-with-findings and only exit 1 as failure — Task 6 tests both exit codes.
3. **amass v5 produces no text file (writes to its asset DB)**: reading results via the wrong command yields zero subdomains silently — Task 2 tests the parse step against a captured `amass` output sample, and the task fails loudly on an empty/missing DB.
4. **A crawled JS bundle contains a secret that mantis reports**: the finding's `http_url` must point at the asset it came from, not the temp audit dir, or remediation can't locate it — Task 7 tests the path mapping.
5. **A profile the migration can't map** (unknown/garbage engine YAML): must fall back to `normal` and log, never crash `initiate_scan` — Task 8 tests an unmappable engine.

---

## File Structure

| File | Responsibility |
|---|---|
| `web/limes/identity.py` (create) | `ScanIdentity` dataclass; load from project/target; encrypt/decrypt secret header values; render for each tool; temp-file lifecycle |
| `web/limes/profiles.py` (create) | `PROFILES` (quick/normal/thorough/passive) → depth, limits, timeouts, assay profile name; `resolve_profile(engine)`; `map_engine_to_profile(yaml)` |
| `web/limes/pipeline/__init__.py` (create) | stage registry + ordered DAG builder used by `initiate_scan` |
| `web/limes/pipeline/discovery.py` (create) | amass v5 + subfinder, merge, save via `save_subdomain` |
| `web/limes/pipeline/amass.py` (create) | build amass enum argv; read names back from its asset DB; parse |
| `web/limes/pipeline/resolve.py` (create) | dnsx resolve + wildcard filter |
| `web/limes/pipeline/crawl.py` (create) | katana + gau; collect JS/sourcemaps/.git artifacts dir |
| `web/limes/integrations/assay.py` (create) | build argv, run, map assay JSON findings → `save_vulnerability` kwargs |
| `web/limes/integrations/mantis.py` (create) | run `mantis.audit()` on crawl artifacts; map findings → `save_vulnerability` kwargs |
| `web/limes/integrations/severity.py` (create) | shared severity-string → int map |
| `web/limes/tasks.py` (modify) | rewrite stage tasks; delete removed-tool tasks; new `initiate_scan` workflow |
| `web/limes/definitions.py` (modify) | profile keys; remove dead tool constants |
| `web/scanEngine/...` (modify) | engine form/UI becomes profile selector; data migration |
| `web/Dockerfile` (modify) | pin+trim Go tools, add opengrep, assay, mantis; drop removed tools and Firefox/gecko |
| `web/requirements.txt` (modify) | add `mantis-sast`, `cryptography`; remove `wafw00f` |
| test files under `web/tests/core/` | per task |

---

### Task 1: Scan identity

**Files:**
- Create: `web/limes/identity.py`, `web/tests/core/test_identity.py`
- Modify: `web/requirements.txt` (add `cryptography==43.0.1`), `web/limes/settings.py` (read `LIMES_SECRET_KEY_ENCRYPTION`)

**Interfaces:**
- Produces: `ScanIdentity(user_agent: str, headers: list[Header])` where `Header(name, value, secret: bool)`; `encrypt(value) -> str` / `decrypt(token) -> str` (Fernet, key from `settings.HEADER_ENCRYPTION_KEY`); `ScanIdentity.for_domain(domain) -> ScanIdentity` (reads `Domain.request_headers`); `render_httpx(identity) -> (argv_list, tempfiles)`; `render_header_args(identity, flag='-H') -> (argv_list, tempfiles)`; `write_assay_config(identity, profile, path) -> tempfiles`; `redaction_secrets(identity) -> list[str]`; `cleanup(tempfiles)`. Every renderer returns secret values only inside 0600 temp files; argv contains non-secret headers inline and `@file` refs (httpx/katana support header files) for secrets.

- [ ] **Step 1: Write failing tests**

`web/tests/core/test_identity.py`:
```python
import os

from django.test import SimpleTestCase, override_settings
from cryptography.fernet import Fernet

from limes import identity

KEY = Fernet.generate_key().decode()


@override_settings(HEADER_ENCRYPTION_KEY=KEY)
class EncryptTest(SimpleTestCase):
    def test_roundtrip(self):
        token = identity.encrypt('S3cr3t')
        self.assertNotIn('S3cr3t', token)
        self.assertEqual(identity.decrypt(token), 'S3cr3t')


@override_settings(HEADER_ENCRYPTION_KEY=KEY)
class RenderTest(SimpleTestCase):
    def ident(self, ua='limes/scan', headers=()):
        return identity.ScanIdentity(user_agent=ua, headers=[identity.Header(*h) for h in headers])

    def test_httpx_sets_explicit_ua_and_no_random_agent(self):
        argv, tmp = identity.render_httpx(self.ident(ua='Limes/1.0'))
        self.assertIn('-H', argv)
        self.assertIn('User-Agent: Limes/1.0', argv)
        self.assertNotIn('-random-agent', argv)
        identity.cleanup(tmp)

    def test_headers_with_no_ua_still_get_deterministic_ua(self):
        argv, tmp = identity.render_httpx(self.ident(ua='', headers=[('X-Env', 'test', False)]))
        joined = ' '.join(argv)
        self.assertIn('User-Agent: ', joined)  # a default UA, never empty, never -random-agent
        self.assertNotIn('-random-agent', argv)
        self.assertIn('X-Env: test', argv)
        identity.cleanup(tmp)

    def test_secret_header_not_in_argv(self):
        ident = self.ident(headers=[('Authorization', 'Bearer T0K3N', True)])
        argv, tmp = identity.render_header_args(ident)
        self.assertNotIn('Bearer T0K3N', ' '.join(argv))
        contents = ''.join(open(p).read() for p in tmp)
        self.assertIn('Bearer T0K3N', contents)
        for p in tmp:
            self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)
        identity.cleanup(tmp)
        self.assertFalse(any(os.path.exists(p) for p in tmp))

    def test_redaction_secrets_lists_only_secret_values(self):
        ident = self.ident(headers=[('Authorization', 'Bearer T0K3N', True), ('X-Env', 'test', False)])
        self.assertEqual(identity.redaction_secrets(ident), ['Bearer T0K3N'])

    def test_assay_config_written_with_identity(self):
        ident = self.ident(ua='Limes/1.0', headers=[('X-Env', 'test', False)])
        import tempfile
        path = tempfile.mktemp(suffix='.yaml')
        tmp = identity.write_assay_config(ident, profile='normal', path=path)
        body = open(path).read()
        self.assertIn('Limes/1.0', body)
        self.assertIn('X-Env: test', body)
        self.assertIn('normal', body)
        identity.cleanup(tmp + [path])
```

- [ ] **Step 2: Run to see it fail** — `make test` → ImportError.

- [ ] **Step 3: Implement** `web/limes/identity.py` with `Header`/`ScanIdentity` dataclasses, Fernet encrypt/decrypt using `settings.HEADER_ENCRYPTION_KEY`, a module-level `DEFAULT_UA = 'limes/scan'` used whenever `user_agent` is empty, renderers that write secret headers to `tempfile.NamedTemporaryFile(delete=False)` chmod 0600 and reference them with httpx/katana `-H` file syntax (write non-secret headers inline), `write_assay_config` emitting YAML with `user_agent`, `headers`, `profile`, and `cleanup` unlinking temp files. `settings.py`: `HEADER_ENCRYPTION_KEY = env('LIMES_SECRET_KEY_ENCRYPTION', default=None)` and, when None, derive a stable key from `SECRET_KEY` so dev works (note in code: production must set it).
NOTE in code: header-file syntax differs per tool; httpx/katana accept `-H` repeated and a file — confirm the exact file flag against the installed tool version during Step 4 and adjust the renderer, keeping the tests green.

- [ ] **Step 4: Run tests** — `make test`, identity tests PASS.

- [ ] **Step 5: Commit**

```bash
git add web/limes/identity.py web/tests/core/test_identity.py web/requirements.txt web/limes/settings.py
git commit -m "feat: per-target scan identity with encrypted secret headers"
```

---

### Task 2: amass v5 integration

**Files:**
- Create: `web/limes/pipeline/__init__.py`, `web/limes/pipeline/amass.py`, `web/tests/core/test_amass.py`, `web/tests/core/fixtures/amass_subs_sample.txt`

**Interfaces:**
- Produces: `build_enum_argv(domain, config_dir, active: bool, brute: bool, wordlist: str|None) -> list[str]`; `build_subs_argv(domain, config_dir) -> list[str]`; `parse_subs(output: str, domain: str) -> list[str]` (FQDNs under `domain`, deduped, lowercased); `AmassError`.

- [ ] **Step 1: Capture a real sample** (one-time, documented): run `amass enum -d example.com -timeout 1` then `amass subs -names -d example.com` in the built image and save a few lines to `web/tests/core/fixtures/amass_subs_sample.txt`. If the network blocks it, hand-write a representative sample of `amass subs -names` output (one FQDN per line) and note it in the report.

- [ ] **Step 2: Write failing tests**

`web/tests/core/test_amass.py`:
```python
import pathlib

from django.test import SimpleTestCase

from limes.pipeline import amass

FIX = pathlib.Path(__file__).parent / 'fixtures' / 'amass_subs_sample.txt'


class AmassArgvTest(SimpleTestCase):
    def test_passive_enum(self):
        argv = amass.build_enum_argv('example.com', '/root/.config/amass', active=False, brute=False, wordlist=None)
        self.assertEqual(argv[:2], ['amass', 'enum'])
        self.assertIn('-d', argv)
        self.assertIn('example.com', argv)
        self.assertNotIn('-active', argv)
        self.assertNotIn('-brute', argv)

    def test_active_brute_with_wordlist(self):
        argv = amass.build_enum_argv('example.com', '/root/.config/amass', active=True, brute=True, wordlist='/w.txt')
        self.assertIn('-active', argv)
        self.assertIn('-brute', argv)
        self.assertIn('-w', argv)
        self.assertIn('/w.txt', argv)

    def test_subs_argv(self):
        argv = amass.build_subs_argv('example.com', '/root/.config/amass')
        self.assertEqual(argv[:2], ['amass', 'subs'])
        self.assertIn('-names', argv)

    def test_parse_filters_to_domain_and_dedupes(self):
        out = FIX.read_text()
        names = amass.parse_subs(out, 'example.com')
        self.assertTrue(all(n == 'example.com' or n.endswith('.example.com') for n in names))
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue(all(n == n.lower() for n in names))

    def test_parse_empty_returns_empty(self):
        self.assertEqual(amass.parse_subs('', 'example.com'), [])
```

- [ ] **Step 3: Run to see it fail** — ImportError.

- [ ] **Step 4: Implement** `amass.py`:
```python
"""OWASP Amass v5 integration: run enum, read names from its asset DB."""
DEFAULT_TIMEOUT = 30


class AmassError(Exception):
    pass


def build_enum_argv(domain, config_dir, active, brute, wordlist):
    argv = ['amass', 'enum', '-d', domain, '-dir', config_dir]
    if active:
        argv.append('-active')
    if brute:
        argv.append('-brute')
        if wordlist:
            argv += ['-w', wordlist]
    return argv


def build_subs_argv(domain, config_dir):
    return ['amass', 'subs', '-names', '-d', domain, '-dir', config_dir]


def parse_subs(output, domain):
    seen, names = set(), []
    suffix = '.' + domain.lower()
    for line in output.splitlines():
        name = line.strip().lower()
        if not name:
            continue
        if name == domain.lower() or name.endswith(suffix):
            if name not in seen:
                seen.add(name)
                names.append(name)
    return names
```
`pipeline/__init__.py`: empty for now (populated in Task 5).
NOTE in code (top of amass.py): v5 writes to an asset DB under `-dir`; results are read with `amass subs`, not from a text file. `-dir` is the per-scan config/results dir so runs don't collide.

- [ ] **Step 5: Run tests** — PASS.

- [ ] **Step 6: Commit**
```bash
git add web/limes/pipeline/__init__.py web/limes/pipeline/amass.py web/tests/core/test_amass.py web/tests/core/fixtures/amass_subs_sample.txt
git commit -m "feat: amass v5 enum/subs integration (asset-DB aware)"
```

---

### Task 3: Severity map + assay finding mapping

**Files:**
- Create: `web/limes/integrations/__init__.py`, `web/limes/integrations/severity.py`, `web/limes/integrations/assay.py`, `web/tests/core/test_assay_map.py`, `web/tests/core/fixtures/assay_report_sample.json`

**Interfaces:**
- Produces: `severity.to_int(s: str) -> int` ({critical:4, high:3, medium:2, low:1, info:0, unknown/other:-1}); `assay.build_argv(targets_file, profile, identity_config_path, output_dir, extra_no_flags) -> list[str]`; `assay.DESTRUCTIVE_FLAGS: frozenset`; `assay.parse_report(report_json: dict) -> list[dict]` where each dict is `save_vulnerability` kwargs (`name, severity, type, http_url, description, remediation, cvss_score, cve_ids, cwe_ids, references, request, response, source='assay', matcher_name`); `assay.AssayError`.

- [ ] **Step 1: Create the sample** `web/tests/core/fixtures/assay_report_sample.json` — a minimal real-shape report: `{"version":"...","tool":"assay","scan_result":{"findings":[{"id":"...","type":"sql-injection","severity":"high","confidence":"confirmed","title":"SQLi","url":"https://t.test/a?id=1","parameter":"id","cwe":["CWE-89"],"top10":["A03:2025"],"cvss":8.2,"evidence":"...","request":"GET ...","response":"HTTP/1.1 500","remediation":"Parameterize","verified":true}],"technologies":["nginx"]},"summary":{}}`

- [ ] **Step 2: Write failing tests**

`web/tests/core/test_assay_map.py`:
```python
import json
import pathlib

from django.test import SimpleTestCase

from limes.integrations import assay, severity

FIX = pathlib.Path(__file__).parent / 'fixtures' / 'assay_report_sample.json'


class SeverityTest(SimpleTestCase):
    def test_map(self):
        self.assertEqual((severity.to_int('critical'), severity.to_int('info'), severity.to_int('weird')), (4, 0, -1))


class AssayArgvTest(SimpleTestCase):
    def test_argv_has_json_profile_and_no_destructive_flags(self):
        argv = assay.build_argv('/t.txt', 'normal', '/id.yaml', '/out', extra_no_flags=[])
        self.assertIn('--json', argv)
        self.assertIn('--profile', argv)
        self.assertIn('normal', argv)
        self.assertFalse(assay.DESTRUCTIVE_FLAGS & set(argv))

    def test_passive_profile(self):
        argv = assay.build_argv('/t.txt', 'passive', '/id.yaml', '/out', extra_no_flags=['--no-postmessage'])
        self.assertIn('passive', argv)
        self.assertIn('--no-postmessage', argv)


class AssayParseTest(SimpleTestCase):
    def test_maps_findings(self):
        report = json.loads(FIX.read_text())
        vulns = assay.parse_report(report)
        self.assertEqual(len(vulns), 1)
        v = vulns[0]
        self.assertEqual(v['severity'], 3)
        self.assertEqual(v['http_url'], 'https://t.test/a?id=1')
        self.assertEqual(v['source'], 'assay')
        self.assertEqual(v['cwe_ids'], ['CWE-89'])
        self.assertAlmostEqual(v['cvss_score'], 8.2)
        self.assertEqual(v['name'], 'SQLi')

    def test_empty_findings(self):
        self.assertEqual(assay.parse_report({'scan_result': {'findings': []}}), [])
        self.assertEqual(assay.parse_report({}), [])
```

- [ ] **Step 3: Run to see it fail** — ImportError.

- [ ] **Step 4: Implement** `severity.py` (the map) and `assay.py`:
```python
from limes.integrations.severity import to_int

DESTRUCTIVE_FLAGS = frozenset({'--h2-reset', '--h2-continuation', '--h2-madeyoureset',
                               '--redos', '--mass-assign', '--proto-pollution-server', '--rate-limit'})


class AssayError(Exception):
    pass


def build_argv(targets_file, profile, identity_config_path, output_dir, extra_no_flags):
    argv = ['assay', 'scan', '-l', targets_file, '--profile', profile,
            '--config', identity_config_path, '--output-dir', output_dir, '--json']
    argv += list(extra_no_flags)
    return argv


def parse_report(report_json):
    result = (report_json or {}).get('scan_result') or {}
    vulns = []
    for f in result.get('findings', []):
        vulns.append({
            'name': f.get('title') or f.get('type', 'assay finding'),
            'type': f.get('type', ''),
            'severity': to_int(f.get('severity', 'unknown')),
            'http_url': f.get('url', ''),
            'description': f.get('description', ''),
            'remediation': f.get('remediation', ''),
            'cvss_score': f.get('cvss'),
            'cvss_metrics': f.get('cvss_vector', ''),
            'cve_ids': [c for c in f.get('cwe', []) if c.upper().startswith('CVE')],
            'cwe_ids': [c for c in f.get('cwe', []) if c.upper().startswith('CWE')],
            'references': f.get('references', []),
            'request': f.get('request', ''),
            'response': f.get('response', ''),
            'matcher_name': f.get('parameter', ''),
            'source': 'assay',
        })
    return vulns
```
(assay puts both CVE and CWE in its `cwe` array per the finding schema; split by prefix.)

- [ ] **Step 5: Run tests** — PASS.

- [ ] **Step 6: Commit**
```bash
git add web/limes/integrations web/tests/core/test_assay_map.py web/tests/core/fixtures/assay_report_sample.json
git commit -m "feat: map assay JSON findings to the vulnerability model"
```

---

### Task 4: mantis finding mapping

**Files:**
- Create: `web/limes/integrations/mantis.py`, `web/tests/core/test_mantis_map.py`
- Modify: `web/requirements.txt` (add `mantis-sast`)

**Interfaces:**
- Produces: `mantis.audit_dir(code_dir, packs: list[str], llm: bool=False) -> list[dict]` (calls `mantis.audit`); `mantis.map_finding(finding: dict, source_url: str) -> dict` (`save_vulnerability` kwargs, `source='mantis'`, `http_url=source_url`, severity mapped from ERROR/WARNING/INFO); `mantis.MantisError`.

- [ ] **Step 1: Write failing tests** `web/tests/core/test_mantis_map.py`:
```python
from unittest import mock

from django.test import SimpleTestCase

from limes.integrations import mantis


class MantisMapTest(SimpleTestCase):
    def test_map_finding(self):
        f = {'rule_id': 'secret-aws-key', 'severity': 'ERROR', 'confidence': 'HIGH',
             'path': 'static/app.js', 'start_line': 12, 'end_line': 12,
             'message': 'AWS key', 'metadata': {'cwe': 'CWE-798'}, 'verdict': 'TRUE'}
        v = mantis.map_finding(f, source_url='https://t.test/app.js')
        self.assertEqual(v['source'], 'mantis')
        self.assertEqual(v['http_url'], 'https://t.test/app.js')
        self.assertEqual(v['severity'], 3)  # ERROR -> high
        self.assertIn('secret-aws-key', v['name'])
        self.assertEqual(v['cwe_ids'], ['CWE-798'])

    def test_severity_bands(self):
        self.assertEqual(mantis.map_finding({'severity': 'WARNING', 'metadata': {}}, 's')['severity'], 2)
        self.assertEqual(mantis.map_finding({'severity': 'INFO', 'metadata': {}}, 's')['severity'], 0)

    def test_audit_dir_calls_api(self):
        with mock.patch('limes.integrations.mantis._audit', return_value=[{'severity': 'INFO', 'metadata': {}, 'path': 'a', 'rule_id': 'r'}]) as m:
            out = mantis.audit_dir('/code', packs=['secrets', 'web'])
        m.assert_called_once()
        self.assertEqual(len(out), 1)
```

- [ ] **Step 2: Run to see it fail** — ImportError.

- [ ] **Step 3: Implement** `mantis.py` with `_audit` wrapping `from mantis import audit`, `MANTIS_SEVERITY = {'ERROR': 3, 'WARNING': 2, 'INFO': 0}`, `map_finding` building kwargs (name = `f"{rule_id}: {message[:120]}"`, `cwe_ids` from `metadata.cwe` if present as a list of one), and `audit_dir` calling `_audit(code_dir, packs=packs, llm=llm)` guarded by try/except → `MantisError`.

- [ ] **Step 4: Run tests** — PASS.

- [ ] **Step 5: Commit**
```bash
git add web/limes/integrations/mantis.py web/tests/core/test_mantis_map.py web/requirements.txt
git commit -m "feat: map mantis SAST findings to the vulnerability model"
```

---

### Task 5: Profiles

**Files:**
- Create: `web/limes/profiles.py`, `web/tests/core/test_profiles.py`
- Modify: `web/limes/definitions.py` (profile key constants)

**Interfaces:**
- Produces: `PROFILES: dict[str, Profile]` for `quick|normal|thorough|passive`; `Profile` has `name, crawl_depth, crawl_max_pages, naabu_ports, nmap_enabled, assay_profile, timeouts: dict, nuclei_severities`; `resolve_profile(name) -> Profile` (unknown → normal); `map_engine_to_profile(yaml_configuration: str) -> str` (maps legacy engine YAML to a profile name; unmappable → 'normal').

- [ ] **Step 1: Write failing tests** `web/tests/core/test_profiles.py`:
```python
from django.test import SimpleTestCase

from limes import profiles


class ProfileTest(SimpleTestCase):
    def test_four_profiles(self):
        self.assertEqual(set(profiles.PROFILES), {'quick', 'normal', 'thorough', 'passive'})

    def test_passive_disables_active(self):
        self.assertEqual(profiles.PROFILES['passive'].assay_profile, 'passive')
        self.assertFalse(profiles.PROFILES['passive'].nmap_enabled)

    def test_resolve_unknown_is_normal(self):
        self.assertEqual(profiles.resolve_profile('nope').name, 'normal')

    def test_thorough_deeper_than_quick(self):
        self.assertGreater(profiles.PROFILES['thorough'].crawl_depth, profiles.PROFILES['quick'].crawl_depth)

    def test_map_engine_thorough(self):
        y = "subdomain_discovery: {}\nport_scan: {'enable_nmap': true}\nvulnerability_scan: {}\nfetch_url: {}\ndir_file_fuzz: {}"
        self.assertEqual(profiles.map_engine_to_profile(y), 'thorough')

    def test_map_engine_passive(self):
        self.assertEqual(profiles.map_engine_to_profile("subdomain_discovery: {}"), 'passive')

    def test_map_engine_garbage_is_normal(self):
        self.assertEqual(profiles.map_engine_to_profile(":::not yaml:::"), 'normal')
```

- [ ] **Step 2: Run to see it fail** — ImportError.

- [ ] **Step 3: Implement** `profiles.py` with a frozen `Profile` dataclass and the four presets (quick: depth 1, no nmap, assay quick; normal: depth 2, nmap on, assay normal; thorough: depth 3, nmap on, assay thorough; passive: depth 1, no nmap, assay passive). `map_engine_to_profile` wraps `yaml.safe_load` in try/except (garbage → 'normal'); maps by which legacy stages are present (has vuln_scan + dir_fuzz → thorough; has port_scan+fetch_url → normal; discovery-only → passive; else normal).

- [ ] **Step 4: Run tests** — PASS.

- [ ] **Step 5: Commit**
```bash
git add web/limes/profiles.py web/tests/core/test_profiles.py web/limes/definitions.py
git commit -m "feat: scan profiles replace per-tool engine selection"
```

---

### Task 6: DAST stage (assay) task

**Files:**
- Modify: `web/limes/tasks.py` (replace `vulnerability_scan`; delete `nuclei_scan`, `nuclei_individual_severity_module`, `dalfox_xss_scan`, `crlfuzz_scan`, `s3scanner`, `waf_detection` and their parsers `parse_dalfox_result`, `parse_crlfuzz_result`, `parse_s3scanner_result`; **also delete the entire OSINT subtree** `osint`, `osint_discovery`, `dorking`, `theHarvester`, `h8mail` — the new workflow (Task 8) does not use OSINT, and `osint`/`osint_discovery` are blocking poll-loop coordinators (`while not job.ready(): sleep(5)`) that cause the 0A residual orchestrate-pool deadlock. They must be DELETED, not merely disabled, so no blocking-coordinator code remains.)
- Create: `web/tests/core/test_vuln_stage.py`
- Modify: `web/limes/celery_routing.py` (drop ALL deleted task names from `TASK_PLAN`: the nuclei/dalfox/crlfuzz/s3/waf set AND `osint`, `osint_discovery`, `dorking`, `theHarvester`, `h8mail`)
- Modify: `web/tests/core/test_no_joins.py` (tighten the 0A AST invariant: after this task, `blocking_tasks()` must be the EMPTY set — assert no `@app.task` in `tasks.py` contains a `while not <x>.ready()` / `.get()` poll loop at all. This closes the residual deadlock permanently rather than relying on queue routing.)

**Coherence:** deleting `osint` leaves `initiate_scan`'s workflow (`group(subdomain_discovery, osint)`) referencing a gone task. In THIS task also change that group to just `subdomain_discovery.si(ctx=ctx)` (drop the `osint.si(...)`) so `tasks.py` stays coherent; Task 8 does the full workflow restructure. Run `make test` + a `python3 -c "import limes.tasks"` to confirm the module still imports.

**0A residual closed here:** phase 0A rerouted the 4 blocking coordinators (`osint`, `osint_discovery`, `vulnerability_scan`, `nuclei_scan`) to `orchestrate` as a mitigation, but a ≥4-concurrent-scan deadlock remained because blocking parents and blocking children shared that pool. This task removes all four (`vulnerability_scan` → assay with no poll loop; `nuclei_scan` deleted; `osint`/`osint_discovery` deleted), eliminating the root cause. The tightened `test_no_joins.py` (empty blocking set) is the regression guard. The combined 0A+0B branch is only deadlock-safe-at-any-concurrency after this task lands.

**Interfaces:**
- Consumes: `integrations.assay`, `identity.ScanIdentity`, `profiles`, `limes.commands.run`, `save_vulnerability`.
- Produces: `vulnerability_scan` task runs assay over the scan's crawled URLs and saves findings; returns a count. Exit code 2 (fail-on) is success-with-findings; exit 1 is `AssayError`.

- [ ] **Step 1: Write failing tests** `web/tests/core/test_vuln_stage.py` — test the pure helper, not the Celery machinery:
```python
from unittest import mock

from django.test import SimpleTestCase

from limes.integrations import assay


class ExitCodeTest(SimpleTestCase):
    def test_exit_2_is_findings_not_error(self):
        self.assertTrue(assay.is_success(2))
        self.assertTrue(assay.is_success(0))
        self.assertFalse(assay.is_success(1))
```
Add `is_success(code) -> bool` (`code in (0, 2)`) to `assay.py` and its unit above.

- [ ] **Step 2: Run to see it fail** — AttributeError.

- [ ] **Step 3: Implement** `is_success` in `assay.py`; rewrite `vulnerability_scan` in `tasks.py` to: gather crawled http URLs (`get_http_urls`), write a targets file, build the scan identity (`ScanIdentity.for_domain`) + assay config, build argv via `assay.build_argv` with the profile's `assay_profile`, run with `commands.run(..., secrets=identity.redaction_secrets(...), timeout=profile.timeouts['dast'])`, raise `AssayError` only when `not is_success(rc)`, read `assay-report.json` from the output dir, map with `assay.parse_report`, and `save_vulnerability` each (attach subdomain/endpoint by matching `http_url`). Delete the removed tasks and their parsers. Remove the deleted names from `TASK_PLAN`.

- [ ] **Step 4: Run tests** — `make test`, all PASS; `python3 -c "import limes.tasks"` clean.

- [ ] **Step 5: Commit**
```bash
git add web/limes/tasks.py web/limes/celery_routing.py web/tests/core/test_vuln_stage.py
git commit -m "feat: replace nuclei/dalfox/crlfuzz/wafw00f/s3 tasks with assay DAST stage"
```

---

### Task 7: Code-audit stage (mantis) + crawl artifacts

> Execution note: this task needs design judgment (how katana/gau artifacts are downloaded and mapped to source URLs depends on tool behavior confirmed at build time). Dispatch on a standard model, not the cheap tier, and expect the implementer to fill in the download mechanics within the interfaces below.

**Files:**
- Create: `web/limes/pipeline/crawl.py`, `web/tests/core/test_crawl_artifacts.py`
- Modify: `web/limes/tasks.py` (rewrite `fetch_url` to katana+gau only, collect artifacts; add `code_audit` task)

**Interfaces:**
- Produces: `crawl.collect_code_artifacts(results_dir) -> str` (dir of downloaded JS/sourcemaps/.git content, returns its path); `crawl.artifact_source_url(artifact_path, mapping) -> str`; `code_audit` task runs `mantis.audit_dir` on the artifacts dir and saves findings mapped back to their source URL.

- [ ] **Step 1: Write failing tests** `web/tests/core/test_crawl_artifacts.py` for `artifact_source_url` (given a saved-path→URL mapping file, returns the URL; unknown path → the asset root). Keep katana/gau argv building covered by a small `build_katana_argv`/`build_gau_argv` test (scope `-fs fqdn`, depth from profile, identity header file present).

- [ ] **Step 2–5:** implement, test, commit as the prior tasks. `fetch_url` becomes katana+gau only (gospider/hakrawler/waybackurls deleted), still merging via phase 0A's `merge_url_files`, and additionally saving `.js`/`.map`/`.git` artifacts with a path→URL map. `code_audit` runs after the DAST group. Commit:
```bash
git commit -m "feat: katana+gau crawl with code-artifact collection and mantis audit stage"
```

---

### Task 8: New workflow + profile wiring + engine migration

**Files:**
- Modify: `web/limes/tasks.py` (`initiate_scan` workflow), `web/scanEngine/` (form/views/templates → profile selector), create `web/scanEngine/migrations/000X_profiles.py` data migration
- Create: `web/tests/core/test_workflow.py`

**Interfaces:**
- Consumes: `profiles.resolve_profile`, `profiles.map_engine_to_profile`.
- Produces: `initiate_scan` builds `chain(group(discovery), resolve, port_scan, http_crawl, group(fetch_url+code_audit, vulnerability_scan, screenshot), report)` driven by the resolved profile; the data migration stamps each existing `EngineType` with a mapped profile (stored in a new `EngineType.profile` CharField, default 'normal').

- [ ] **Step 1: Write failing tests** `web/tests/core/test_workflow.py`: `map_engine_to_profile` over a few seeded `EngineType.yaml_configuration` values returns valid profile names; an unmappable config yields `normal` and does not raise.

- [ ] **Step 2–5:** implement; add `EngineType.profile` + migration (makemigrations --check must pass); rewrite the `initiate_scan` workflow block; point the engine add/edit UI at a profile dropdown (keep raw YAML editable for advanced users but ignored by the pipeline — note this in the UI). Commit:
```bash
git commit -m "feat: profile-driven scan workflow; migrate engines to profiles"
```

---

### Task 9: Dockerfile pin + trim, identity wired into httpx/katana

**Files:**
- Modify: `web/Dockerfile`, `web/limes/tasks.py` (`http_crawl` uses `identity.render_httpx`), `web/limes/pipeline/crawl.py` (katana uses identity), `web/requirements.txt` (remove `wafw00f`), `web/limes/definitions.py` (remove dead tool constants)
- Create: `web/tests/core/test_http_identity.py`

**Interfaces:**
- Consumes: `identity.render_httpx`, `identity.render_header_args`.
- Produces: `http_crawl` applies the scan identity (explicit UA, no `-random-agent`); image contains only the pipeline tools + assay + mantis + opengrep.

- [ ] **Step 1: Write failing test** `web/tests/core/test_http_identity.py`: a helper `httpx_identity_args(domain)` returns argv containing `-H User-Agent: ...` and never `-random-agent`, including when the domain's identity has headers but empty UA (Review Focus #1).

- [ ] **Step 2–3:** implement the helper and wire it into `http_crawl` (replace the `-random-agent` line and manual `-H` building); wire katana in `crawl.py`. Dockerfile: replace the `go install` block with the pinned list (subfinder, dnsx, naabu, httpx, katana, nuclei, gau, amass v5) at the Global-Constraints versions; drop gospider, hakrawler, waybackurls, unfurl, gf, chaos, ffuf, tlsx, dalfox, crlfuzz, s3scanner, oneforall/sublist3r/ctfr/theHarvester/CMSeeK/goofuzz clones, Firefox, geckodriver, EyeWitness, selenium; add opengrep binary, `pip install mantis-sast`, and build+copy the assay binary from a builder stage (`FROM golang:1.27 AS assay-build` cloning `/home/kali/project/trc/assay` — vendor the source into the build context or `go install github.com/TyrusRC/assay/cmd/assay@<pinned>`). Remove `wafw00f` from requirements and dead constants from definitions.

- [ ] **Step 4:** `make test` PASS; `docker compose -p limes-test -f docker-compose.test.yml build test` succeeds; `docker run --rm limes-next:local sh -c 'amass version; subfinder -version; assay --version; mantis --version; opengrep --version'` prints versions.

- [ ] **Step 5: Commit**
```bash
git commit -m "build: pin+trim tools to the default pipeline; wire scan identity into httpx/katana"
```

---

### Task 10: End-to-end pipeline check + docs

**Files:**
- Create: `docs/benchmarks/2026-10-phase0b-pipeline.md`

- [ ] **Step 1:** bring up the stack (`make up`), add the local `labtarget` (from 0A's `docker-compose.bench.yml`) plus a deliberately-vulnerable local target if available (e.g. a local juice-shop container on the limes network — lab only), run one `normal` scan against it via the UI/API, and confirm: subdomains discovered, endpoints crawled, assay ran (findings saved with `source='assay'`), mantis ran on collected JS, no destructive assay flags in any `Command` row, scan reaches SUCCESS, no stuck scan.
- [ ] **Step 2:** verify secret-header redaction end to end: set a secret header on the target, run a scan, grep the `Command` table / `commands.txt` for the secret value → absent.
- [ ] **Step 3:** record results and the final tool list / image size in the benchmark doc; commit.

---

## Notes carried from 0A

- The reaper, time limits, three queues, atomic bookkeeping, Redis cache, pgbouncer, gunicorn and secret-free `.env` are already in place; 0B must not regress them (e.g. new tasks must appear in `TASK_PLAN`, must be idempotent for acks_late, and must not reintroduce `shell=True`).
