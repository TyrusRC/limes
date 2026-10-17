# Waivers, notes and fix forecast Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a team waive a tracked issue (as an accepted risk with an expiry, or as a false positive), discuss it in notes, and forecast the score impact of fixing chosen issues. The headline score excludes active waivers, and the raw score stays visible.

**Architecture:**
- `limes/waivers.py` holds the waiver and note rules (create, revoke, active, note).
- `limes/scoring.py` becomes `limes-score-v3`: it drops actively waived (asset, key) pairs from the adjusted score, keeps a raw score, and adds `forecast()`.
- `limes/alerts` suppresses new and regressed events for waived issues and announces expiries through the daily `expire_waivers` task.
- DRF endpoints and an Issues page expose all of it.

**Tech Stack:** Django 3.2, DRF, Celery beat, PostgreSQL, jQuery and DataTables.

**Spec:** `docs/superpowers/specs/2026-10-18-waivers-remediation-design.md`

## Global Constraints

- **Waiver kinds (exact strings):** `accepted_risk` and `false_positive`.
  - Both require a non-blank reason of at most 5000 characters.
  - `accepted_risk`: `expires_at` is required and must be in (now, now + 365 days]. If it is omitted it defaults to now + 90 days.
  - `false_positive`: `expires_at` is optional, and when given must be in (now, now + 365 days].
- **Active waiver:** `revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now)`. A waiver stops counting at exactly `expires_at`, with no wait for any task. There is at most one active waiver per issue: creating one revokes any current active one (`revoked_by` = the new creator).
- **Score:**
  - `VERSION = 'limes-score-v3'`;
  - the adjusted `score`/`grade` exclude active waivers;
  - `raw_score`/`raw_grade` ignore waivers;
  - snapshots store both (`ScoreSnapshot.raw_score`);
  - waived pairs are matched on the **normalized** key (`scoring.issue_key`, the same function `TrackedIssue` uses).
- **Alerts:**
  - while active, a waiver suppresses `issue_new` and `issue_regressed` for its issue, but `issue_fixed` is still recorded;
  - the new kind is `waiver_expired`. It is immediate when its issue is open with severity ≥ 3, and digest-only otherwise;
  - each expiry is announced once (`IssueWaiver.expiry_notified`).
- **Permissions:** writes (waive, revoke, add note) require `PERM_MODIFY_SCAN_RESULTS` (the `HasPermission` + `permission_required` pattern in `api/views.py`). Reads are login-only, like the other asset APIs. Every endpoint checks that the issue belongs to the named project.
- **Escaping:** finding names, check ids, reasons and notes are user or scanner text and are escaped everywhere they render.
- **Celery:** `expire_waivers` runs every 86400.0 seconds (beat), routed `(ORCHESTRATE, 15 * MIN)`, in a module added to `CELERY_IMPORTS`.
- **Style:**
  - 4 spaces in `limes/*.py`, `startScan/*` and tests;
  - tabs in `api/views.py`, `asset.js`, the new page JS, and the template script blocks;
  - `api/urls.py` is CRLF.
- **Tests:** `docker compose -p limes-test -f docker-compose.test.yml run --rm test python3 manage.py test <dotted.path>`; the controller may use an equivalent local runner. No network.
- **Commits:** identity `TyrusRC <63230297+TyrusRC@users.noreply.github.com>`, no AI attribution, no push without an explicit user yes.

## Review Focus

1. **A waiver whose `expires_at` just passed must count as not waived immediately**, before `expire_waivers` runs. This is the roadmap's waiver-expiry invariant. Task 2 `test_waiver_expiry_restores_penalty_at_expires_at`.
2. **Long finding names (hashed keys) must waive correctly**, so the score drops the right penalty. Task 2 `test_long_key_waiver_matches`.
3. **A second waiver on the same issue** must leave exactly one active waiver. Task 1 `test_new_waiver_revokes_previous`.
4. **A read-only user, or another project's issue id,** must never waive, revoke or add notes. Task 4 `test_writes_need_permission_and_project`.
5. **A finding name or note containing `<script>`** renders as text on the Issues page. Task 5's real-UI check.

---

### Task 1: Waiver and note models and rules

**Files:**
- Modify: `web/startScan/asset_models.py`:
  - add `IssueWaiver(issue FK TrackedIssue related_name='waivers', kind CharField(16), reason TextField, created_by FK User null SET_NULL, created_at default now, expires_at null, revoked_at null, revoked_by FK User null SET_NULL related_name='+', expiry_notified BooleanField default False)`;
  - add `IssueNote(issue FK TrackedIssue related_name='notes', author FK User null SET_NULL, text TextField, created_at default now)`;
  - add `ScoreSnapshot.raw_score IntegerField null`;
  - put both new models in `__all__`.

  Then run `makemigrations startScan -n waivers_notes`.
- Create: `web/limes/waivers.py`
- Test: `web/tests/core/test_waivers.py`

**Interfaces:**
- Produces:
  - `waivers.KINDS = ('accepted_risk', 'false_positive')`;
  - `waivers.DEFAULT_DAYS = 90`, `waivers.MAX_DAYS = 365`;
  - `waivers.WaiverError(ValueError)`;
  - `waivers.active_waiver(issue, now=None) -> IssueWaiver | None`;
  - `waivers.create_waiver(issue, kind, reason, user, expires_at=None, now=None) -> IssueWaiver`, which raises `WaiverError` with a plain message on invalid input;
  - `waivers.revoke_waiver(issue, user, now=None) -> bool` (False when nothing was active);
  - `waivers.add_note(issue, user, text) -> IssueNote`, which raises `WaiverError` on blank text or text over 5000 characters.

- [ ] **Step 1: Write the failing tests** (`WaiverRulesTest(TestCase)`, with a `TrackedIssue` built directly):
  - `test_accepted_risk_defaults_to_90_days`: no `expires_at` gives `expires_at == now + 90 days`.
  - `test_validation`, where each case raises `WaiverError`:
    - an unknown kind;
    - a blank or whitespace reason;
    - a reason of 5001 characters;
    - `accepted_risk` expiring at now − 1 minute or at now + 366 days;
    - `false_positive` expiring at now + 366 days.

    `false_positive` with no expiry is valid.
  - `test_new_waiver_revokes_previous`: two `create_waiver` calls leave exactly one active waiver, and the first has `revoked_at` set and `revoked_by` set to the second user.
  - `test_active_respects_expiry_and_revocation`: active at `expires_at − 1s`, inactive at `expires_at`. After `revoke_waiver`, `active_waiver` is None, and a second revoke returns False.
  - `test_notes`: `add_note` stores the author and text. Blank text and text of 5001 characters raise.
- [ ] **Step 2: Run them.** `... test tests.core.test_waivers` fails with an ImportError.
- [ ] **Step 3: Implement** the models, migration and `waivers.py`. `create_waiver` does its revoke-then-create inside `transaction.atomic()`, with `select_for_update` on the issue row.
- [ ] **Step 4: Run them**, plus `makemigrations --check --dry-run`. Expected: OK, then `No changes detected`.
- [ ] **Step 5: Commit** "Add issue waivers and notes with their rules".

### Task 2: `limes-score-v3`: adjusted and raw scores, forecast

**Files:**
- Modify: `web/limes/scoring.py` (`issue_key` moves here from `limes/alerts/issues.py`, which imports it from scoring; also `waived_keys`, the `_penalties` waived filter, `project_score`, `asset_breakdown`, `forecast`, `VERSION`, and `snapshot_scores` storing `raw_score`), `web/limes/alerts/issues.py` (import `issue_key` from scoring)
- Test: `web/tests/core/test_waivers.py` (`ScoreV3Test`), plus updating the `'limes-score-v2'` assertions in existing tests to `'limes-score-v3'`

**Interfaces:**
- Consumes: `waivers.active_waiver` semantics (Task 1).
- Produces:
  - `scoring.issue_key(key: str) -> str`, unchanged behaviour;
  - `scoring.waived_keys(project, now=None) -> set[tuple[int, str]]`;
  - `project_score(project)` gains `raw_score`, `raw_grade` and `waived_count`, with the adjusted value in `score`/`grade`;
  - `asset_breakdown(asset)` rows gain `'waived': bool`, and waived rows don't count in its `score`;
  - `scoring.forecast(project, issue_ids: list[int], now=None) -> {'score': int | None, 'grade': str, 'delta': int | None}`. The ids are `TrackedIssue` ids in that project; unknown ids are ignored.

- [ ] **Step 1: Write the failing tests:**
  - `test_waiver_excludes_penalty_from_adjusted_score_only`:
    - a host with one high finding and an open `TrackedIssue` for it;
    - before waiving, `score == raw_score == 799`;
    - after `create_waiver(accepted_risk)`, `score == 950`, `raw_score == 799` and `waived_count == 1`;
    - in `asset_breakdown`, that row has `waived` True and its score is 950.
  - `test_waiver_expiry_restores_penalty_at_expires_at`: with `now = expires_at − 1s` the score is 950; with `now = expires_at` it is 799. Pass `now` explicitly where the function takes it. No `expire_waivers` call.
  - `test_false_positive_without_expiry_stays_waived`.
  - `test_long_key_waiver_matches`: a finding named with 400 characters, its `TrackedIssue` using `issue_key(name)`, waived, gives adjusted 950.
  - `test_forecast`:
    - for two open issues (high, then medium), `forecast([high])` returns the score without the high penalty and `delta == forecast.score − current adjusted score`;
    - an unknown id or another project's issue id changes nothing;
    - forecasting a waived issue adds nothing.
  - `test_snapshot_stores_raw_score`: `snapshot_scores()` writes `raw_score`.
- [ ] **Step 2: Run them.** Expected: failures and `KeyError: 'raw_score'`.
- [ ] **Step 3: Implement.** The waived filter applies only to the adjusted path. `forecast` reuses the adjusted computation with the extra exclusions.
- [ ] **Step 4: Run** `tests.core.test_waivers tests.core.test_scoring tests.core.test_alerts tests.core.test_risk_checks tests.core.test_asset_api tests.core.test_dashboard_stats`. Expected: OK.
- [ ] **Step 5: Commit** "Score waived issues out of the headline as limes-score-v3 and forecast fixes".

### Task 3: Alerts: suppression and expiry announcements

**Files:**
- Modify: `web/limes/alerts/events.py` (`KINDS` gains `'waiver_expired'`, plus the immediacy rule), `web/limes/alerts/issues.py` (skip new and regressed events for actively waived issues)
- Create: `web/limes/alerts/waiver_tasks.py` (Celery task `expire_waivers`)
- Modify: `web/limes/settings.py` (beat entry plus `CELERY_IMPORTS`), `web/limes/celery_routing.py`
- Test: `web/tests/core/test_waivers.py` (`WaiverAlertsTest`)

**Interfaces:**
- Consumes: `waivers.active_waiver` (Task 1) and `events.record` / `safe_record`.
- Produces: the `expire_waivers(now=None) -> {'expired': n}` task. For each waiver with `revoked_at IS NULL AND expires_at <= now AND expiry_notified = False`, it records one `waiver_expired` event and sets `expiry_notified=True`, using a conditional update so the event fires exactly once.

- [ ] **Step 1: Write the failing tests:**
  - `test_rules`: `is_immediate('waiver_expired', key, 3)` is True and `is_immediate('waiver_expired', key, 2)` is False.
  - `test_waived_issue_does_not_alert`:
    - an open issue is waived;
    - `sync_issues` with its severity rising to 4 emits nothing;
    - after its fix, `issue_fixed` is emitted;
    - when it reappears while still waived, nothing is emitted.
  - `test_expire_waivers_announces_once`:
    - an expired waiver on an open high issue gives one immediate `waiver_expired` event;
    - a second run gives no new event;
    - a revoked waiver gives none;
    - a not-yet-expired waiver gives none.
  - `test_beat_and_routing`: `expire_waivers` is in beat at 86400.0, routed `(ORCHESTRATE, 15 * MIN)`, and its module is in `CELERY_IMPORTS`.
- [ ] **Step 2: Run them.** Expected: failures and ImportError.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `tests.core.test_waivers tests.core.test_alerts`, then the full suite. Expected: OK.
- [ ] **Step 5: Commit** "Silence alerts for waived issues and announce expired waivers".

### Task 4: Issue API

**Files:**
- Modify: `web/api/views.py` (5 views), `web/api/urls.py` (CRLF), `web/api/serializers.py` if a serializer is used
- Test: `web/tests/core/test_issue_api.py`

**Interfaces:**
- Consumes: `waivers.*` (Task 1) and `scoring.forecast` (Task 2).
- Produces:
  - `GET /api/issues/?project=<slug>[&severity=1-4][&source=check|finding][&waived=true|false]` returns open issues as `[{id, asset, key, title, source, severity, first_seen, last_seen, waiver: {kind, reason, expires_at, created_by, created_at} | null, note_count}]`, ordered by severity desc, then `first_seen`. `title` is the catalogue title for check keys, otherwise the key.
  - `POST /api/action/issue/waive/` takes `{project, issue_id, kind, reason, expires_at?}` (ISO datetime) and returns `{status, message, waiver?}`.
  - `POST /api/action/issue/revoke/` takes `{project, issue_id}`.
  - `GET /api/issue/notes/?project=&issue_id=` returns `[{author, text, created_at}]`, oldest first. `POST /api/issue/notes/` takes `{project, issue_id, text}`.
  - `POST /api/score_forecast/` takes `{project, issues: [ids]}` and returns `forecast(...)`.

- [ ] **Step 1: Write the failing tests:**
  - `test_list_filters_and_shape`;
  - `test_waive_and_revoke_round_trip`: after waiving, the list shows the waiver, and after revoking, `waiver` is null;
  - `test_waive_validation_errors_are_messages`: a bad kind, a blank reason, or an expiry over 365 days gives `{status: False, message: ...}`, never a 500;
  - `test_notes_round_trip`;
  - `test_forecast_endpoint`;
  - `test_writes_need_permission_and_project`: an auditor gets 403 on waive, revoke and note POST. An admin posting another project's issue id under this project gets `status False`, and nothing is created. A list request with an unknown project gives `[]` or 404. An unauthenticated request is not given 200.
- [ ] **Step 2: Run them.** Expected: 404s and failures.
- [ ] **Step 3: Implement**, following the existing `ConfirmAsset` / `SetAssetCadence` patterns (`_load_asset`-style project scoping, `HasPermission`).
- [ ] **Step 4: Run** `tests.core.test_issue_api tests.core.test_asset_api`. Expected: OK.
- [ ] **Step 5: Commit** "Expose issues, waivers, notes and score forecast over the API".

### Task 5: Issues page and raw-score display

**Files:**
- Create: `web/startScan/templates/startScan/issues.html` (route `/scan/<slug>/issues`, name `issues`, in `startScan/urls.py` and `startScan/views.py` like `assets`), `web/static/custom/issues.js`
- Modify:
  - the navigation template that links Assets: add "Issues" next to it;
  - `web/static/custom/asset.js` (the score card shows "raw N" when `raw_score != score`; the modal risk table marks waived rows "waived");
  - `web/dashboard/templates/dashboard/index.html` (the risk card shows the raw score when it differs).

- [ ] **Step 1: Implement.**
  - The page has a DataTable from `/api/issues/`, with filters for severity, source and waived.
  - The row modal holds the waive form (kind select, reason textarea, a date input defaulting to +90 days for `accepted_risk`), a revoke button, the notes list and an add-note box.
  - Row checkboxes call `/api/score_forecast/` and show "Forecast if fixed: N (G), ±D".
  - Escape every field with a local copy of the `asset_esc` pattern. Never use `innerHTML` with unescaped data.
- [ ] **Step 2: Verify.**
  - Run `node --check` on both JS files, the template check, and the full suite.
  - Then the real UI. Seed an open high issue whose finding name is `<script>alert(1)</script>`, plus a second issue, and log in as a user with modify rights.
  - On the Issues page:
    - the name shows as text, with no script element and no dialog;
    - waiving with a reason makes the row show "waived" and the score card's raw value;
    - revoking clears it;
    - adding a note shows it in the thread;
    - ticking the high issue shows a forecast with a positive delta;
    - there are no console errors.
  - As an auditor user, the waive and note buttons are hidden or disabled, and a forced POST gets 403.
- [ ] **Step 3: Commit** "Add the Issues page with waivers, notes and fix forecast".
