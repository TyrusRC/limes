# Alert rules and integrations

Default alerts are unchanged: high-signal changes alert immediately (in-app, the install-wide chat settings, the optional
`LIMES_ALERT_WEBHOOK_*` webhook) and the rest arrive in the daily digest. **Alert rules** (Configure > Alert rules) add
delivery on top of that. With no rule, nothing here runs.

## A rule

| Field | Meaning |
|---|---|
| Events | One or more change kinds (`issue_new`, `issue_fixed`, `score_dropped`, `asset_new`, ...). |
| Minimum severity | 1 low to 4 critical. Applies only to events that carry a severity; others pass. |
| Tags | Any-of asset tags. An event without an asset (the project score) never satisfies a tag condition. |
| Score drop | For `score_dropped` / `score_changed`: the score must be N points below its peak in the last W days. |
| Send to | `in_app`, `email`, `webhook`, `slack`, `jira`. |

An enabled rule matches an event created after the rule was. An event goes to each channel once, however many rules ask
for it (an email goes once to the union of the recipients). Always-immediate kinds keep their default immediate
delivery; a rule that also asks for `in_app` does not add a second notification for an event already shown there.
Rules run when events are delivered (after each scan stage and the daily score snapshot), for events from the last hour.

## Channels and integrations

Integration settings are per project (the same page). Secrets (webhook URL and signing secret, Slack URL, Jira token) are
encrypted with the Fernet key `LIMES_SECRET_KEY_ENCRYPTION` (derived from the Django secret if unset; set it in
production), never logged, and never returned: the API and page show only "set" and the last four characters.

* **Webhook**: signed JSON, `X-Limes-Signature: sha256=<HMAC-SHA256 of the body>`, the same body as the default webhook.
* **Slack**: an incoming-webhook URL; falls back to the install-wide Slack setting. Text is escaped (`& < >`) and capped.
* **Email**: Django SMTP backend, `LIMES_EMAIL_*` (see README). No host: the rule shows "email: not configured".
* **Jira Cloud**: base URL, account email, API token, project key, issue type, labels. One issue per new issue event
  (`issue_new`), created through REST v3; the key is stored on the tracked issue, so a retry, a second rule or a re-fire
  never makes a duplicate. Summary and description are plain, escaped, length-capped text. "Test create issue" creates a
  real issue and reports its key.

Every outbound URL must be public https: other schemes, credentials in the URL, loopback, private, link-local and
internal names are refused, the host is resolved once and the connection pinned to the vetted address, and redirects are
not followed. Calls time out after 10 seconds; transient failures (network, 429, 5xx) retry three times with backoff
(30 s, 60 s, 120 s). The outcome is kept on the rule (`last_sent`, `last_error`) and shown on the page. A failure never
reaches the scan pipeline.

## Limits

Each project may send `LIMES_ALERT_RULE_<CHANNEL>_PER_HOUR` rule alerts per channel per hour (defaults: in-app 60, email 30,
Slack 60, webhook 120, Jira 20). Events over the cap are not sent; the rule's `suppressed` count grows and, once the window
has ended, the channel gets one "N more alert events were held back" message (Jira gets none). If the cache is down the
cap fails closed: rule sends pause. Emails go one per recipient. "Test" and "Test create issue" are limited to 10 an hour
per user. A secret that no longer decrypts is reported as "secret unreadable - re-enter" and never replaced by another
destination; masks show the last four characters only for secrets of 20 or more characters.

## REST

`GET/POST /api/alert_rules/`, `GET/PATCH/DELETE /api/alert_rules/<id>/`, `POST /api/alert_rules/<id>/test/`,
`GET/PUT /api/alert_integration/`, `POST /api/alert_integration/jira_test/`. The project is `?project=<slug>` or in the
body; an id from another project is a 404. Needs the permission that gates Notification Settings.
