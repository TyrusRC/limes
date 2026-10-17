# Change alerts, daily digest and signed webhook

Status: the user said "just do your suggestion" on 2026-10-17, so the proposal below is approved as stated. Every detail here is my call unless marked otherwise.
Builds on `main` at `7732a7e`: the A4/v2 score (`limes/scoring.py`), risk checks (`RiskCheck`), A5b continuous scans, `ScoreSnapshot`, and A3c attribution.

## Intent

The user wants Limes to be an UpGuard alternative. Item 2 on the UpGuard gap list is alerts: UpGuard sends custom notifications in-app, by email or by webhook when risk changes.

The goal is that a person hears about a meaningful change to their attack surface without watching the dashboard, and is not flooded.

## Goals

- **A change log.** Each change is recorded once as a `ChangeEvent`, whatever the number of scans that see it.
- **Immediate alerts** for high-signal changes only. Everything else goes into one daily digest per project, sent only when something happened.
- **Delivery** through the existing chat channels (Slack, Discord, Telegram, Lark via `send_notif`), in-app notifications (`InAppNotification`), and a new signed generic webhook.
- **A noise guard:** at most 10 immediate alerts per project per hour. Anything over that goes into the digest.

## Non-goals

- Email. Limes has no mail configuration yet.
- Subdomain-takeover alerts. Limes has no takeover detection yet.
- Per-user alert preferences.
- Jira or Zapier connectors. The webhook is the integration point.
- Waivers. The tracked-issue model is built so they can be added later.

## Anti-goals

- **The same change alerting again on every scan.**
- **A first scan of a large estate flooding the channels.** On a project's first issue sync, every issue is recorded silently as the baseline.
- **Secrets in webhook or chat payloads.** Evidence is copied only from `RiskCheck.evidence`, which already holds no request secrets. The webhook secret never leaves the server except as the signature.
- **Sending alerts to destinations the operator didn't configure.** Webhook and chat targets come only from settings or the existing `Notification` row.

## Design (my calls)

### Tracked issues: the state that makes "new", "fixed" and "back" possible

The model is `TrackedIssue(project, asset, key, source, severity, status, first_seen, last_seen, fixed_at, reopened)`:
- `key` is the score category (finding template/name, or check id);
- `source` is `finding` or `check`;
- `status` is `open` or `fixed`;
- `reopened` counts how many times the issue came back;
- it is unique on `(asset, key)`.

`sync_issues(project, now) -> list[ChangeEvent]` reads the **current open set** from the score's own inputs: the per-asset category → severity map that `scoring` builds from baselines and fresh failed checks. It then diffs that set against `TrackedIssue`:

| Change | Event |
|---|---|
| A key not seen before | `issue_new` |
| An open issue no longer present | `issue_fixed`, and the issue is marked fixed |
| A fixed issue present again | `issue_regressed`, and `reopened` goes up by one |
| An open issue whose severity rose | `issue_new` at the new severity |

**Unassessed is not fixed:** an asset that becomes unassessed (for example, stale check data) does **not** fix its issues. Issues are only marked fixed for assets still assessed.

**First sync:** when a project has no `TrackedIssue` rows yet, the issues are created silently and no events are emitted.

### Other event sources

- **Score:** `snapshot_scores` compares today's snapshot with the previous one. A lower grade letter, or a drop of 50 points or more, emits `score_dropped`. Any other change is recorded as `score_changed` for the digest.
- **Attribution:** a domain auto-confirmed in `apply_decisions` emits `asset_auto_confirmed`.
- **Lifecycle:** an asset going from `active` to `missing` emits `asset_missing`.
- **New owned assets** are not stored as events. The digest counts them from `Asset.first_seen`, and likewise counts new review-queue candidates.

### What is immediate

An event is immediate when one of these is true:
- `issue_new` or `issue_regressed` with severity high or critical;
- `issue_new` or `issue_regressed` whose key is `tls.cert_expired` or `tls.cert_expiring`, whatever its severity;
- an exposed risky service (`net.exposed_*`, any severity);
- `score_dropped`;
- `asset_auto_confirmed`.

Everything else is digest-only.

### Model

`ChangeEvent(project, kind, severity, asset nullable, title, detail JSON, immediate bool, created_at, notified_at nullable, digested_at nullable)`.

### Delivery

`deliver_immediate(project, now)` runs after each scan's `report` step and after `snapshot_scores`. It sends un-notified immediate events, oldest first, up to the hourly cap of `ALERT_HOURLY_CAP = 10` per project, counted by `notified_at` in the last hour. Events beyond the cap stay un-notified and go into the next digest.

For each event:
1. an `InAppNotification` with a link to the asset or dashboard;
2. `send_notif(message, title=...)` to the configured chat channels;
3. the webhook, when it is configured.

`send_digest()` is a beat task that runs daily. Per project, it sends everything not yet digested, plus counts of new owned assets and new candidates from the last 24 hours. A project with nothing to report gets no message.

**Webhook:**
- configured by `LIMES_ALERT_WEBHOOK_URL` and `LIMES_ALERT_WEBHOOK_SECRET` from the environment;
- the request is a `POST` with a JSON body `{"event": kind, "project": slug, "severity", "title", "asset", "detail", "created_at", "id"}`;
- header `X-Limes-Signature: sha256=<hex HMAC of the raw body with the secret>`;
- 5 second timeout, never retried within the same run;
- a failure is logged and leaves the event marked notified, so a dead webhook never blocks chat or in-app delivery;
- a URL that isn't https is refused unless the setting `LIMES_ALERT_WEBHOOK_ALLOW_HTTP=true` is set.

### Where it runs

- **`sync_issues` and `deliver_immediate`:** run at the end of `report` for the scan's project, but only when the scan succeeded (the same condition as `finalize_lifecycle`).
- **`snapshot_scores`:** emits score events, then calls `deliver_immediate`.
- **`send_digest`:** a new beat entry every 86400 seconds, routed like the other orchestration tasks.

### UI

The dashboard's "This week" card gains a "Recent changes" list of the last 10 events. There is no settings page: the webhook comes from the environment, and the chat channels use the existing notification settings page.

## Left to the builder

- Message wording.
- The in-app icon and status mapping.
- The digest layout, as long as it is one message per project per day.
- Exact query shapes.
