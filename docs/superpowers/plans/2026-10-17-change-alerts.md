# Change alerts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Record each attack-surface change once as a `ChangeEvent`, send high-signal ones immediately (in-app, chat, signed webhook; capped at 10 per project per hour), and send everything else in one daily digest per project.

**Architecture:**
- **`web/limes/alerts/` is a new package:**
  - `issues.py` keeps `TrackedIssue` in step with the score's current open set and emits issue events;
  - `events.py` holds event kinds, the immediacy rule and `record()`;
  - `deliver.py` sends immediate events (in-app, chat, webhook);
  - `digest.py` holds the daily beat task.
- **Hooks into existing code:**
  - scan `report` (on success): sync, then deliver;
  - `snapshot_scores`: score events, then deliver;
  - `apply_decisions`: auto-confirm event;
  - `finalize_lifecycle`: missing event.
- The dashboard shows the last 10 events.

**Tech Stack:** Django 3.2, Celery 5.4 with beat, PostgreSQL, `requests==2.31.0`, stdlib `hmac`/`hashlib`.

**Spec:** `docs/superpowers/specs/2026-10-17-change-alerts-design.md`

## Global Constraints

- **Event kinds (exact strings):** `issue_new`, `issue_fixed`, `issue_regressed`, `score_dropped`, `score_changed`, `asset_auto_confirmed`, `asset_missing`.
- **Severity ints** follow the findings scale: critical 4, high 3, medium 2, low 1. `None` means the event has no severity.
- **Immediate rule:** an event is immediate when any of these holds:
  - `issue_new` or `issue_regressed` with severity ≥ 3;
  - `issue_new` or `issue_regressed` whose key is `tls.cert_expired` or `tls.cert_expiring`, or starts with `net.exposed_`;
  - the kind is `score_dropped` or `asset_auto_confirmed`.

  Everything else is digest-only.
- **Score drop:** `score_dropped` when the grade letter is worse than the previous snapshot's, or when `prev.score - today.score >= 50`. Any other score difference is `score_changed`. No previous snapshot, or a `None` score on either side, means no event.
- **First sync** for a project (no `TrackedIssue` rows yet) creates the rows silently with zero events.
- **Unassessed is not fixed:** an issue is marked fixed only if its asset is still assessed.
- **Cap:** `ALERT_HOURLY_CAP = 10` immediate deliveries per project, per rolling hour (counted by `notified_at`). Over-cap events stay `notified_at=None` and go into the next digest. `deliver_immediate` sends only events with `notified_at IS NULL AND digested_at IS NULL`, so a digested event is never sent again.
- **Webhook:**
  - configured by `settings.ALERT_WEBHOOK_URL = env('LIMES_ALERT_WEBHOOK_URL', default='')`, `ALERT_WEBHOOK_SECRET = env('LIMES_ALERT_WEBHOOK_SECRET', default='')` and `ALERT_WEBHOOK_ALLOW_HTTP = env.bool('LIMES_ALERT_WEBHOOK_ALLOW_HTTP', default=False)`;
  - a JSON `POST`, with header `X-Limes-Signature: sha256=<hmac_sha256(secret, raw_body).hexdigest()>` and `Content-Type: application/json`;
  - `timeout=5`, no retry;
  - an empty URL or secret disables it;
  - a non-https URL is refused unless `ALLOW_HTTP` is set;
  - any `requests` exception is logged, and the event is still marked notified.
- **Payload:** `{"id", "event", "project", "severity", "title", "asset", "detail", "created_at"}`. `detail` holds only Limes-derived data (keys, counts, scores, and the check evidence already stored in `RiskCheck.evidence`), never request secrets.
- **Celery:**
  - `send_digest` is scheduled every `86400.0` seconds;
  - `limes.alerts.digest` is added to `CELERY_IMPORTS`;
  - routing is `'send_digest': (ORCHESTRATE, 15 * MIN)`.
- **Style:**
  - 4 spaces in `limes/alerts/*`, `scoring.py`, `startScan/*`, `inventory.py` and `attribution.py`;
  - tabs in `control.py`, `stages.py` and the dashboard template script.
- **Tests:** no network. The chat and webhook senders are injected or patched.
- **Commits:** identity `TyrusRC <63230297+TyrusRC@users.noreply.github.com>`, no AI attribution, no push without an explicit user yes.

## Review Focus

1. **Repeated scans seeing the same issue must not re-alert.**
   - Task 1 `test_second_sync_emits_nothing`;
   - Task 3 `test_delivered_events_are_not_resent`.
2. **A first sync on a large estate must not flood.** Task 1 `test_first_sync_is_silent`.
3. **Stale check data must not read as "fixed" and then "regressed".** Task 1 `test_unassessed_asset_is_not_fixed`.
4. **A dead or slow webhook must not block chat or in-app delivery**, and must not be retried in a loop. Task 3 `test_webhook_failure_does_not_block_other_channels`.
5. **The webhook must be authentic and safe.** The signature must verify, http must be refused by default, and no secret may appear in the payload. Task 3 `test_webhook_signature_verifies` and `test_http_webhook_refused_by_default`.

---

### Task 1: Tracked issues, events and `sync_issues`

**Files:**
- Modify: `web/startScan/asset_models.py`. Add these models and include both in `__all__`, then run `makemigrations startScan -n change_alerts`:
  - `TrackedIssue(project FK, asset FK related_name='tracked_issues', key CharField(255), source CharField(10), severity IntegerField, status CharField(8) default 'open', first_seen, last_seen, fixed_at null, reopened IntegerField default 0)`, with `unique_together=('asset','key')`;
  - `ChangeEvent(project FK related_name='change_events', kind CharField(32), severity IntegerField null, asset FK null on_delete SET_NULL, title CharField(300), detail JSONField default dict, immediate BooleanField, created_at default now, notified_at null, digested_at null)`, with index `(project, created_at)`.
- Modify: `web/limes/scoring.py`. Add `current_issues(project, now=None) -> tuple[dict[int, dict[str, int]], set[int]]`, which returns (asset_id → {key: severity}, assessed asset ids). Build it from the existing `_penalties` and `assessed_assets`, sharing one `baselines` call.
- Create: `web/limes/alerts/__init__.py`, `web/limes/alerts/events.py`, `web/limes/alerts/issues.py`
- Test: `web/tests/core/test_alerts.py`

**Interfaces:**
- Produces:
  - `events.KINDS` (tuple of the 7 kinds);
  - `events.is_immediate(kind: str, key: str | None, severity: int | None) -> bool`;
  - `events.record(project, kind, title, severity=None, asset=None, detail=None, key=None) -> ChangeEvent`, which sets `immediate` via `is_immediate`;
  - `issues.sync_issues(project, now=None) -> list[ChangeEvent]`;
  - `TrackedIssue.source` is `'check'` when `key in limes.checks.catalogue.CHECKS`, otherwise `'finding'`.

- [ ] **Step 1: Write the failing tests** in `test_alerts.py`.

  `ImmediacyTest(SimpleTestCase).test_rules` has one assertion per Global Constraints rule:
  - `('issue_new', 'web.csp_missing', 1)` gives False;
  - `('issue_new', 't1', 3)` gives True;
  - `('issue_regressed', 'tls.cert_expiring', 2)` gives True;
  - `('issue_new', 'net.exposed_ftp', 2)` gives True;
  - `('issue_fixed', 't1', 4)` gives False;
  - `('score_dropped', None, None)` gives True;
  - `('asset_auto_confirmed', None, None)` gives True;
  - `('score_changed', None, None)` gives False;
  - `('asset_missing', None, None)` gives False.

  `SyncTest(TestCase)` fakes `scoring.current_issues` with `mock.patch` returning `(issues, assessed)`, and checks:
  - `test_first_sync_is_silent`: 3 issues on a project with no rows give `[]`, and 3 open `TrackedIssue` rows exist;
  - `test_second_sync_emits_nothing`: the same input twice gives `[]` the second time;
  - `test_new_fixed_regressed`:
    - after a baseline sync, adding key `t2` (sev 3) emits one `issue_new` that is immediate;
    - removing `t2` (asset still assessed) emits `issue_fixed` with `immediate` False and `status == 'fixed'`;
    - adding `t2` back emits `issue_regressed` (immediate) with `reopened == 1`;
  - `test_severity_rise_is_new`: `t1` going from 1 to 3 emits `issue_new` at severity 3;
  - `test_unassessed_asset_is_not_fixed`: an issue disappears because its asset dropped out of `assessed`, which gives no event and the row stays `open`;
  - `test_events_are_per_project`: project B's issues never create rows or events in project A.

  `CurrentIssuesTest(TestCase).test_matches_score_inputs`: an owned host with one high baseline finding and one fresh failed low check returns `({host.id: {'t1': 3, 'web.csp_missing': 1}}, {host.id, ...})`.
- [ ] **Step 2: Run them.** `... dj.sh test tests.core.test_alerts` fails with an ImportError.
- [ ] **Step 3: Implement** the models, migration, `current_issues`, `events.py` and `issues.py`. `last_seen` is updated on every sync that still sees the issue.
- [ ] **Step 4: Run them**, plus `tests.core.test_scoring` and `makemigrations --check --dry-run`. Expected: OK, then `No changes detected`.
- [ ] **Step 5: Commit** "Track issues and record change events once per change".

### Task 2: Score, auto-confirm and missing events

**Files:**
- Modify: `web/limes/scoring.py` (`snapshot_scores`), `web/limes/tasks/attribution.py` (`apply_decisions`), `web/limes/tasks/inventory.py` (`finalize_lifecycle`)
- Test: `web/tests/core/test_alerts.py` (`OtherEventsTest`)

**Interfaces:**
- Consumes: `events.record` (Task 1).
- Produces:
  - `scoring.score_event(prev: ScoreSnapshot | None, today: ScoreSnapshot) -> tuple[str, str] | None`, returning (kind, title) or None;
  - `snapshot_scores` records the score event after `update_or_create`, comparing against the latest snapshot dated before today.

- [ ] **Step 1: Write the failing tests:**
  - `test_score_event_rules`:
    - 850 A → 790 B gives `score_dropped` (grade fell);
    - 800 A → 750 B gives `score_dropped`;
    - 940 A → 880 A gives `score_dropped` (60 points);
    - 900 → 880 gives `score_changed`;
    - 880 → 900 gives `score_changed`;
    - no previous snapshot gives None;
    - a None score on either side gives None;
    - an equal score gives None.
  - `test_snapshot_records_score_event`: yesterday's snapshot is 950/A and today's project score is 599/C, so `snapshot_scores()` creates one `score_dropped` event with `immediate=True`. Running it again the same day creates no second event (count stays 1).
  - `test_auto_confirm_records_event`: reuse the A5a decision setup (a verified delegation with the flag on), so `apply_decisions` confirms a candidate and one `asset_auto_confirmed` event exists for that asset. With the flag off and `would_auto_confirm` set, no event is created.
  - `test_missing_transition_records_event`: `finalize_lifecycle` moving an asset from active to missing records one `asset_missing` event. An asset whose miss count goes up while it stays active records none.
- [ ] **Step 2: Run them.** Expected: failures, and an AttributeError for `score_event`.
- [ ] **Step 3: Implement.** Snapshot de-duplication: record the score event only when `update_or_create` *created* today's row.
- [ ] **Step 4: Run** `tests.core.test_alerts tests.core.test_scoring tests.core.test_attribution_decisions tests.core.test_inventory_writes`. Expected: OK.
- [ ] **Step 5: Commit** "Record score drops, auto-confirmations and missing assets as change events".

### Task 3: Immediate delivery

**Files:**
- Create: `web/limes/alerts/deliver.py`
- Modify: `web/limes/settings.py` (the 3 webhook settings from Global Constraints)
- Test: `web/tests/core/test_alerts.py` (`DeliverTest`)

**Interfaces:**
- Consumes: `ChangeEvent` (Task 1).
- Produces:
  - `deliver.ALERT_HOURLY_CAP = 10`;
  - `deliver.deliver_immediate(project, now=None, chat=None, post=None) -> int`, returning the number delivered. `chat` defaults to `limes.tasks.notifications.send_notif` (called as `chat(message, title=title)`), and `post` defaults to `requests.post`;
  - `deliver.payload(event) -> dict`;
  - `deliver.sign(body: bytes, secret: str) -> str` (returns `'sha256=' + hexdigest`).

- [ ] **Step 1: Write the failing tests:**
  - `test_sends_immediate_only_oldest_first`: 2 immediate events and 1 digest-only event mean `chat` is called twice, in creation order. Both get `notified_at` set, and the digest-only event stays None. An `InAppNotification` exists for each immediate event.
  - `test_delivered_events_are_not_resent`: a second call sends 0.
  - `test_hourly_cap`:
    - 12 immediate events mean 10 are sent and 2 keep `notified_at=None`;
    - with 10 delivered 30 minutes ago, a new event sends 0;
    - with them delivered 61 minutes ago, it sends 1.
  - `test_webhook_signature_verifies`: with `override_settings` for the URL `https://hook.test/x` and secret `s3cr3t`, the fake `post` captures `data` and `headers`. `hmac.compare_digest(headers['X-Limes-Signature'], sign(data, 's3cr3t'))` holds, `json.loads(data)['event'] == 'issue_new'`, and `'s3cr3t' not in data.decode()`.
  - `test_http_webhook_refused_by_default`: an `http://` URL means `post` is never called and chat is still sent. With `ALERT_WEBHOOK_ALLOW_HTTP=True`, `post` is called.
  - `test_webhook_failure_does_not_block_other_channels`: `post` raises `requests.exceptions.ConnectTimeout`, yet chat and in-app still happen. The event is marked notified, and the call returns normally.
  - `test_no_webhook_configured`: an empty URL or secret means `post` is never called.
- [ ] **Step 2: Run them.** Expected: ImportError.
- [ ] **Step 3: Implement.** Send the body as `json.dumps(payload, sort_keys=True).encode()` and sign exactly those bytes. Each event is delivered once to every channel, and a failure in one channel never stops the others.
- [ ] **Step 4: Run them.** Expected: OK.
- [ ] **Step 5: Commit** "Deliver immediate change alerts in-app, to chat and to a signed webhook".

### Task 4: Digest and wiring

**Files:**
- Create: `web/limes/alerts/digest.py` (the `send_digest` task)
- Modify:
  - `web/limes/tasks/control.py` (`report`: after `finalize_lifecycle`, on the same success condition, call `sync_issues(project)` and then `deliver_immediate(project)`; neither may raise out of `report`);
  - `web/limes/scoring.py` (`snapshot_scores` calls `deliver_immediate` per project after recording);
  - `web/limes/settings.py` (beat entry and `CELERY_IMPORTS`);
  - `web/limes/celery_routing.py`
- Test: `web/tests/core/test_alerts.py` (`DigestTest`, `WiringTest`)

**Interfaces:**
- Consumes: `sync_issues` (Task 1) and `deliver_immediate`/`payload` (Task 3).
- Produces:
  - `digest.build_digest(project, now=None) -> str | None` returns the message text, or None when there is nothing to report;
  - the `send_digest(chat=None)` task returns `{'projects': n, 'sent': m}`, sends one chat message (and one in-app notification) per project with content, and sets `digested_at` on the included events.

- [ ] **Step 1: Write the failing tests:**
  - `test_digest_includes_undigested_events_and_counts`:
    - the digest includes one `issue_fixed`, one over-cap immediate event that was never notified, 2 owned assets with `first_seen` in the last 24 hours, and 1 candidate created in the last 24 hours;
    - the message mentions each event title, "2 new owned assets" and "1 new candidate";
    - afterwards every included event has `digested_at`, and an immediate event that was already notified is **not** repeated;
    - a later `deliver_immediate(project)` sends 0, because the over-cap event was digested.
  - `test_empty_project_sends_nothing`: `build_digest` returns None, and `send_digest` sends 0 for that project.
  - `test_digest_is_per_project`: two projects give two messages, each with only its own events.
  - `WiringTest.test_successful_report_syncs_and_delivers`: patch `limes.alerts.issues.sync_issues` and `limes.alerts.deliver.deliver_immediate`. Run the `report` path for a successful scan run (reuse the existing report tests' setup in `tests/core`): both are called once with the scan's project. For a failed scan, neither is called. If `sync_issues` raises, `report` still completes.
  - `test_beat_and_routing`: `CELERY_BEAT_SCHEDULE` has `send_digest` at 86400.0, `TASK_PLAN['send_digest']` is `(ORCHESTRATE, 15 * MIN)`, and `'limes.alerts.digest'` is in `CELERY_IMPORTS`.
- [ ] **Step 2: Run them.** Expected: ImportError, plus the wiring assertion failures.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `tests.core.test_alerts` plus the module that tests `report`. Then run the full suite. Expected: OK.
- [ ] **Step 5: Commit** "Send a daily change digest and hook alerts into scans and snapshots".

### Task 5: Recent changes on the dashboard

**Files:**
- Modify: `web/dashboard/stats.py` (`asm_stats` adds `recent_changes`: the last 10 `ChangeEvent` rows of the project, newest first, as `{kind, title, severity, created_at, asset}`), `web/dashboard/templates/dashboard/index.html` (a "Recent changes" list in the This week card, with the empty state "No changes recorded yet.")
- Test: `web/tests/core/test_dashboard_stats.py`

**Interfaces:**
- Consumes: `ChangeEvent` (Task 1).

- [ ] **Step 1: Write the failing test:** `test_recent_changes_newest_first_and_scoped`. 12 events in project A and 1 in project B give 10 entries for A, newest first, with none from B.
- [ ] **Step 2: Run it.** Expected: KeyError.
- [ ] **Step 3: Implement.** The template relies on Django auto-escaping only; no `|safe`.
- [ ] **Step 4: Verify.**
  - Run the test, the template check and the full suite.
  - Then the real UI: seed events, including a title containing `<script>alert(1)</script>`, and open `/acme/dashboard/`.
  - The list shows the titles as text, with no `<script>` element and no dialog.
  - An empty project shows the empty state.
  - There are no console errors.
- [ ] **Step 5: Commit** "Show recent changes on the dashboard".
