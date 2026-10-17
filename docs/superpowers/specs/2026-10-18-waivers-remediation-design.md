# Waivers, false positives, notes and fix forecasting

Status: the user said "just do your suggestion" on 2026-10-18, so the proposal below is approved as stated. Every detail is my call unless marked otherwise.
Builds on `main` at `90e9723`: `TrackedIssue` (one row per asset and issue key, open or fixed), `limes-score-v2` (`limes/scoring.py`), change alerts (`ChangeEvent`, digest), and risk checks.

## Intent

The user wants Limes to be an UpGuard alternative. UpGuard lets a team do three things with an issue:
- **accept the risk** for a while, with a justification and an expiry date;
- **mark it as a false positive**;
- **plan remediation** by seeing how fixing chosen issues would change the rating.

People can also discuss an issue in notes. Without these, a team that has decided to live with an issue, or knows a finding is wrong, sees a permanently worse score and repeated alerts. The score then stops reflecting what they control.

## Goals

- **Waivers on a tracked issue,** of two kinds:
  - `accepted_risk`: a reason is required, and the expiry is required, defaulting to 90 days, at most 365;
  - `false_positive`: a reason is required, and the expiry is optional.

  A waiver can be revoked. Everything is recorded: who, when and why, for both waiving and revoking.
- **Two scores:**
  - a waiver-adjusted score, which is the headline and excludes actively waived issues;
  - a raw score, shown alongside, which ignores waivers.

  Snapshots store both. The model version becomes `limes-score-v3`.
- **Expiry is immediate.** The moment a waiver expires, the issue counts again. A daily task records a `waiver_expired` change event (digest) and stops treating the issue as waived. This is the roadmap's required "waiver expiry" invariant test.
- **Alert suppression:** while an issue is actively waived, `issue_new` and `issue_regressed` events for it are not emitted. Fixes are still recorded.
- **Notes:** a plain-text comment thread per tracked issue, with author and time.
- **Fix forecast:** choose open issues and see the score and grade the project would have if they were fixed or waived. This is a read-only what-if.
- **An Issues page** for each project:
  - **list:** open tracked issues (asset, issue, severity, first seen, waiver status), with filters for severity, source and waived;
  - **per-issue actions:** waive (choosing the kind), revoke, and notes;
  - **forecast:** tick checkboxes to see the forecast score.

## Non-goals

- Ticketing (Jira) and assignment. The webhook covers integrations.
- Approval workflows, where a second person approves a waiver.
- Sharing waivers with vendors.
- Bulk waive by rule (for example, "all CSP findings on *.dev").
- Remediation requests sent by email.

## Anti-goals

- **A waiver silently outliving its expiry.** It must stop counting as waived exactly at `expires_at`, even before the daily task runs.
- **Waivers hiding issues from the raw score**, or making them disappear from the Issues list. Waived issues stay visible and labelled.
- **Anyone without edit rights waiving, revoking or adding notes.** Read-only roles may view only.
- **Attacker-controlled finding names or evidence breaking the Issues page.** Everything is escaped.

## Design (my calls)

### Models (`startScan/asset_models.py`)

- `IssueWaiver(issue FK TrackedIssue related_name='waivers', kind CharField(16), reason TextField, created_by FK User null, created_at, expires_at null, revoked_at null, revoked_by FK User null, expiry_notified BooleanField default False)`.
  - **Active** means `revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now)`.
  - At most one active waiver per issue. Creating a new one revokes the previous one.
- `IssueNote(issue FK TrackedIssue related_name='notes', author FK User null, text TextField(max 5000), created_at)`.
- `ScoreSnapshot` gains `raw_score IntegerField null`.

### Scoring (`limes/scoring.py`)

- `waived_keys(project, now) -> set[tuple[asset_id, key]]` returns the active waivers' issue (asset, key) pairs. Keys must be compared in the **normalized form** `TrackedIssue` uses (long keys hashed by `limes.alerts.issues`), so one shared normalizer is used in both places.
- `_penalties(..., waived=None)` drops waived (asset, key) pairs when given.
  - `project_score` returns `score`/`grade` (adjusted), `raw_score`/`raw_grade`, and `waived_count`.
  - `asset_breakdown` marks waived penalty rows `'waived': True` and leaves them out of its score.
- `forecast(project, issues: list[(asset_id, key)], now=None) -> {'score', 'grade', 'delta'}` computes the adjusted score with those issues also excluded. It is read-only.
- `VERSION = 'limes-score-v3'`. `snapshot_scores` also stores `raw_score`.

### Alerts (`limes/alerts/issues.py`, a new daily task)

- `sync_issues` skips `issue_new` and `issue_regressed` for an issue with an active waiver. `issue_fixed` is still recorded.
- The daily beat task `expire_waivers` records one `waiver_expired` ChangeEvent for each waiver whose `expires_at` has passed, using a per-waiver `expiry_notified` flag (`IssueWaiver.expiry_notified BooleanField default False`) so each is announced once.
  - `waiver_expired` is a new event kind.
  - It is immediate when the issue is still open with severity high or above, and digest-only otherwise.
  - No `issue_new` or `issue_regressed` is emitted for it, because the issue never stopped being tracked as open; it only stops being waived.

### API (`api/views.py`)

| Endpoint | Purpose |
|---|---|
| `GET /api/issues/?project=<slug>&status=open&severity=&source=&waived=` | Open tracked issues, with the active waiver, if any, inline, plus a note count. |
| `POST /api/action/issue/waive/` | Body `{project, issue_id, kind, reason, expires_at?}`. Validates the kind, requires a non-empty reason, requires `expires_at` within (now, now+365d] for `accepted_risk` (default now+90d when omitted), and allows `false_positive` with or without an expiry. |
| `POST /api/action/issue/revoke/` | Body `{project, issue_id}`. |
| `GET` / `POST /api/issue/notes/` | Query or body `{project, issue_id, text}`. |
| `POST /api/score_forecast/` | Body `{project, issues: [issue_id...]}`, returning `forecast(...)`. |

- Writes require `PERM_MODIFY_SCAN_RESULTS`. Reads use the same login-only rule as the other asset APIs.
- Every endpoint checks that the issue belongs to the named project.

### UI

- **The Issues page:** `startScan/templates/startScan/issues.html` at `/scan/<slug>/issues`, linked from the navigation next to Assets.
  - It shows a DataTable of issues.
  - Each row has a modal with the waive form, the revoke button, the note thread and an "add note" box.
  - Selecting checkboxes updates a "Forecast if fixed: 812 (A), +63" banner.
  - All fields go through an escape helper.
- **Other surfaces:**
  - the score card and the dashboard risk card show the raw score next to the adjusted one when they differ;
  - the asset modal's risk table marks waived rows.

## Left to the builder

- The wording, the modal layout, and the exact query shapes.
- The DataTable column set beyond what is listed.
