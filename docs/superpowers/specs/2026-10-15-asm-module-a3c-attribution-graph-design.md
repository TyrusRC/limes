# ASM module — Slice A3c: Attribution graph + ownership confidence

Status: design approved in brainstorming 2026-10-15; awaits user review of this file before planning.
Parent: Limes ASM platform. Builds on A3a (resolution + fail-closed scope guard) and A3b (passive providers, candidates), `main` at `e32f0bd`.
Spec basis: `docs/superpowers/specs/2026-10-07-asm-platform-roadmap-design.md` § "Attribution and graph" (typed evidence with source and first/last seen; confidence decaying per hop, max depth 2; above threshold auto-confirms, middle → review queue, below dropped; every asset shows its "why is this mine?" path; keyword matching uses whole-label brand matches, never substrings) and § "Score" ("published and explainable; no black box").
Platform: Django 3.2 + Celery 5.4 + PostgreSQL, internal package `limes`.

## Module context

ASM slices: A0 ✓ · A1 ✓ · A2 ✓ · A3a ✓ · A3b ✓ · **A3c this slice** · A4 risk scoring · A5 continuous.

## Goal

Turn the candidate queue from a flat list into a ranked one: every candidate gets an explainable ownership confidence computed from typed evidence, the review queue is ordered by it, low-confidence noise is hidden, and only candidates with DNS-control evidence are confirmed automatically.

## Decisions taken in brainstorming

- **Auto-confirm only on control evidence.** A candidate is auto-confirmed (owned → actively scanned) only when its score is ≥ 0.9 **and** it has hop-1 DNS-control evidence. Every automatic decision is audited and reversible with Reject.

**Amendment from spec self-review (stricter than the brainstorm wording):** anyone can point their domain's MX — or, with vanity nameservers on a shared DNS provider, even NS — at our hosts without our consent, then aim the domain's A records at a victim; if that counted as control, our scanner would attack the victim. So: (1) MX is ordinary evidence, never control; (2) NS is control only if the candidate actually resolves while its NS set is under owned roots (a lame delegation proves nothing); (3) auto-confirm additionally requires at least one hop-1 `cert` or `ip` fact, which an outsider cannot fake without controlling one of our names or sitting on one of our IPs.
- **Evidence-fact table + published scoring function** (not free-text parsing, not a graph database).

## Evidence available (found in code, 2026-10-15)

crt.sh certificate co-tenancy (A3b), InternetDB hostnames on owned IPs (A3b), dnsx A/AAAA/CNAME (A3a). Not available: NS/MX (dnsx can add them — resolver traffic only, never target traffic) and WHOIS registrant (mostly redacted; deferred).

**Amendment to the approved design:** shared-ASN evidence (proposed weight 0.2) is deferred — candidates are neither resolved nor RIPEstat-enriched, so there is no data path without adding provider calls per candidate.

## Scope

**In:** `AssetFact` evidence table; NS/MX collection for candidate domains via dnsx; per-project brand keywords; the scoring module (`attribution-v1`); applying decisions (auto-confirm / rank / hide); confidence and its explanation in the API and Assets UI.

**Out (later):** shared-ASN evidence; favicon hashes, tech fingerprints, SaaS provider and cloud-account connectors; WHOIS registrant; any change to how owned assets are scanned.

## Design

### 1. Evidence facts (`startScan/asset_models.py`)

- New model `AssetFact(asset FK, kind, value, source, first_seen, last_seen)`, unique on `(asset, kind, value)`; kinds `cert`, `ip`, `ns`, `mx`. Indexed on `(kind, value)` so assets sharing a fact are found with one query.
- `inventory.record_fact(asset, kind, value, source)` upserts and refreshes `last_seen`.
- Recorded by:
  - `run_crtsh`: `cert:<id>` on the owned root **and** on each co-tenant candidate of that certificate;
  - `run_internetdb`: `ip:<address>` on each candidate created from hostnames on an owned IP;
  - new NS/MX collection (§2): `ns:<host>` / `mx:<host>` on candidate root domains.
- Brand matches are computed at scoring time, not stored.

### 2. NS/MX for candidates (`limes/pipeline/dnsx.py`, `limes/tasks/attribution.py`)

- `dnsx.build_ns_mx_argv(hosts_file, output_file)` → `dnsx -l <file> -a -ns -mx -resp -json -silent -o <file>` (A is needed to prove the delegation works); `dnsx.parse` extended to return `ns` and `mx` lists (normalized hostnames; MX values may carry a priority prefix in dnsx output — strip it).
- `attribution.collect_dns(project, results_dir, run=commands.run)` resolves NS/MX for the project's `candidate` root domains (at most 2 000 per run, NOTE naming the ceiling), records facts, best-effort like `resolve_root` (contained errors, 10-minute timeout, re-raises `SoftTimeLimitExceeded`).

### 3. Scoring (`limes/tasks/attribution.py`, version `attribution-v1`)

Published weights (module constants, shown in the UI):

| Evidence | Weight | Counts when |
|---|---|---|
| `ns` control | 0.95 | every NS host of the candidate equals or is under an owned root, and the candidate resolved (A/AAAA) in the same lookup |
| `mx` | 0.60 | a candidate's MX host equals or is under an owned root (never control) |
| `ip` | 0.60 | the candidate shares an `ip` fact value with an owned `ip` asset |
| `cert` | 0.50 | the candidate shares a `cert` fact with an owned asset |
| `brand` | 0.30 | a project brand keyword equals a whole label token of the candidate's registrable label (labels split on `.` and `-`; `acme-shop.com` matches `acme`, `acmesoft.com` does not) |

- **Hop 1:** evidence linking the candidate directly to an owned asset (`owned_root` / `owned_host`) or to an owned root (control, brand).
- **Hop 2:** a fact shared with another candidate whose hop-1 score is ≥ 0.4 contributes `weight × 0.5`. No hop 3.
- **Combination:** noisy-OR, `score = 1 − Π(1 − wᵢ)` over contributions; each distinct (kind, value) counts once at its best hop.
- **Explanation:** `Asset.confidence` (float) and `Asset.confidence_detail` (`{'version', 'score', 'contributions': [{kind, value, via, weight, hop}]}`), both new nullable fields.
- Only `candidate` assets are scored; owned, co-brand, dependency and rejected assets are never touched.

### 4. Decisions

- **Auto-confirm:** score ≥ 0.90 **and** a hop-1 `ns` control contribution **and** at least one hop-1 `cert` or `ip` contribution → `root_domain` candidates become `owned_root`, `hostname` candidates become `owned_host`; `added_by=None`; `decision_reason = 'auto-confirmed (attribution-v1) <score>: <best control evidence>'`; source `attribution` appended; `dashboard.stats.invalidate(project.id)`. Saved with narrow `update_fields`.
- **Review queue:** 0.40 ≤ score < 0.90 (or ≥ 0.90 without control evidence) — stays `candidate`, ranked by score.
- **Hidden:** score < 0.40 — stays `candidate` (never deleted, never re-created), excluded from the Assets list unless "Show low-confidence candidates" is on.
- Thresholds are module constants next to the weights.

### 5. Where it runs

A new `attribution` step at the end of the `passive_intel` stage (after crt.sh, resolve, InternetDB, RIPEstat): `collect_dns` → `score_project(project)` → `apply_decisions(project)`. Wrapped like the other steps (contained failures; stops on the soft time limit). `score_project` is also callable from a management command `manage.py rescore_assets <project_slug>` so weight changes can be applied without a scan.

### 6. Brand keywords (`dashboard.models.Project`)

`Project.brand_keywords = JSONField(default=list, blank=True)` (lower-cased whole tokens; edited in the Django admin, where Project is already registered). Keywords shorter than 4 characters are ignored (NOTE: avoids `ab`-style tokens matching everything).

### 7. API and UI (`api/`, `startScan/templates/startScan/assets.html`, `static/custom/asset.js`)

- `AssetSerializer` gains `confidence` and `confidence_detail`; the datatable gains a sortable Confidence column (colmap updated) and the default list excludes candidates with confidence < 0.4 unless `show_low=1` (checkbox on the page). Project isolation and the no-N+1 test unchanged.
- The detail modal's "Why is this mine" section additionally lists the scoring contributions (kind, value, via, weight, hop) and the auto-decision reason, all through `asset_esc`.

## Data flow

passive_intel: crt.sh (+cert facts) → resolve → InternetDB (+ip facts) → RIPEstat → **attribution**: NS/MX for candidates (+ns/mx facts) → score candidates (hop 1, hop 2, noisy-OR) → auto-confirm with control evidence / rank / hide → UI shows confidence and path.

## Testing

- Fact upsert (unique, last_seen refresh).
- dnsx NS/MX argv + parser (fixture with MX priority prefixes, malformed lines).
- Scoring, table-driven: each weight alone; noisy-OR of two; hop-2 half weight only when the linking candidate's hop-1 score ≥ 0.4; no hop 3; brand whole-label vs substring (`acme-shop.com` vs `acmesoft.com`); keyword < 4 chars ignored; owned/rejected never scored.
- Decisions: working NS control + cert → auto-confirmed with reason, audit source, invalidate called; NS control without corroboration → stays candidate; MX + cert (score ≥ 0.9 possible via noisy-OR) → stays candidate; NS control but candidate did not resolve (lame) → no control contribution; < 0.4 hidden from default list, shown with `show_low=1`; rejected untouched; a rejected asset never becomes a candidate again (A3b invariant still holds).
- Stage wiring: attribution runs last in passive_intel; its failure does not stop the stage.
- API: confidence fields serialized, ordering by confidence, default hiding, project isolation, query count unchanged.
- UI: drive the Assets page and modal in a real browser (ranked list, toggle, contribution list escaped).

## Review focus

1. **No auto-confirm without verified control plus corroboration** — no path (hop 2, brand, MX, a lame NS delegation, rounding) reaches owned without a hop-1 working NS-control fact and a hop-1 cert/ip fact.
2. **Never touch decided assets** — owned, rejected, co-brand, dependency are never re-scored or changed.
3. **Brand matching is whole-label only**.
4. **Explainability** — every score's contributions sum (via noisy-OR) to the stored score and are shown.
5. **Bounded cost** — NS/MX lookups capped per run; scoring is set-based (no per-candidate N+1 over facts).

## Risks

- **Spoofed control evidence** — a third party can name our hosts as their MX or NS without consent. Mitigated by the self-review amendment (MX never control; NS only with a working delegation; auto-confirm also needs a cert/ip corroboration). Residual: a vanity NS hosted on a shared DNS provider plus a co-tenant certificate would still pass — both require effort an outsider rarely has; decisions are audited and reversible. Upgrade path: query our own authoritative servers for the zone's SOA (A5).
- **Weight tuning** — weights are guesses; `rescore_assets` re-applies changes, and the version string marks which model produced each score.

## Amendment after final review (2026-10-15)

The whole-branch review found that the decision path, which controls what the scanner actively attacks, could be steered by an outsider:

1. **NS "working delegation" is spoofable.** NS records read through a recursive resolver are the child zone's own NS RRset. Any domain owner can list our nameservers in their zone while the parent delegation points at their own, and the zone still resolves. A resolved A record therefore does not prove the delegation is ours.
2. **InternetDB IP corroboration is spoofable.** InternetDB's hostnames for an IP include domains whose A records point at it; anyone can point a domain at our IP.
3. **Unbounded chaining.** An auto-confirmed root became an owned root, so its NS, MX and certificates vouched for the next candidate, and so on.

Together, an outsider could get a domain auto-confirmed and then aim our scanner at a victim. Changes:

- **Auto-confirm ships disabled** behind `LIMES_ATTRIBUTION_AUTO_CONFIRM` (setting `ATTRIBUTION_AUTO_CONFIRM`, default off). The qualification check still runs; qualifying candidates stay candidates and carry `confidence_detail.would_auto_confirm = true`, shown in the UI as "Would auto-confirm — NS control is unverified; confirm manually if correct." Decisions are skipped when DNS collection failed, and `rescore_assets` only scores unless `--decide` is given.
- **Corroboration is cert-only.** An owned-IP match still scores 0.60 but never corroborates.
- **Auto-confirmed assets never count as evidence.** Roots, IPs and certificates of assets whose sources include an `attribution` decision are excluded from owned roots, owned IPs and owned certs when scoring. Public-suffix roots (e.g. `co.uk`) are rejected on manual add and ignored when scoring.
- **Hop 2 uses provider-reported facts only** (crt.sh, InternetDB), never DNS-sourced A records.

Note: while hop-1 NS control (0.95) is required, the 0.90 `AUTO_CONFIRM` threshold is redundant; it only matters if control stops being mandatory.

**Upgrade path (A5):** verify the delegation at the parent with a non-recursive NS query to the TLD servers, and require an authoritative SOA answer for the zone from our own nameservers. Only then re-enable auto-confirm by default.
