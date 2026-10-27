# Remediation requests and waivers

## Waivers

A waiver stops an issue counting toward the headline score. It stays in the raw score. Set one on the risk detail
page (or `POST /api/action/issue/waive/`).

- **Scope**: `issue` (this asset only) or `all`. An `all` waiver is one row matched by issue key, so assets and issues
  found later are covered without copying rows; revoking it restores their penalty.
- **Approver** (optional): a member (an active user allowed to change targets; Limes has no per-project membership).
  The waiver is *pending* and does not reduce the score until the approver approves it on the Waivers page. The
  requester cannot approve their own waiver. The approver sees it under Home, My tasks. A pending replacement leaves
  the old waiver in force until approved.
- **Expiry**: accepted risk defaults to 90 days, at most 365. A false positive can be open-ended.
- **Reminder**: `remind_days` (default 7, 1 to 90) before expiry the daily `remind_waivers` task posts one in-app
  notification, and the waiver shows in My tasks from the same moment. It is sent once, never for a revoked, pending
  or expired waiver.
- **Shared**: `shared=false` (default) marks the reason internal-only. NOTE: nothing outside Limes reads waivers yet,
  so the flag is recorded and shown only.

The Waivers page (`/remediation/<project>/waivers`) lists current and past waivers with revoke, approve and reject.

## Remediation requests

Create from the Remediation page, the risk detail page ("Request remediation") or the Issues list (tick risks, then
"Request remediation").

1. Select issues: search, category filter, expandable assets, at most 200 issues.
2. Title, due date, assignee (a member), external recipients (at most 10 addresses) and a message.
3. Review, with the potential score impact. This is `POST /api/score_forecast/`, the same `scoring.forecast` the
   Issues page uses; the detail page shows the same numbers for the issues still open.

External recipients get one email each when `LIMES_EMAIL_HOST` is set; otherwise the request records
`email not configured` and nothing is sent. Subjects are flattened to one line and every address is validated, so a
title or message cannot add headers or recipients.

A request is *active*, *completed* or *archived*. It completes itself when every issue is fixed (checked after each
issue sync); you can also mark it completed, archive it, or reopen it. A request past its due date shows in My tasks
and raises one in-app notification (`remediation_overdue`, daily).

## API

All endpoints are project-scoped (`project` = slug); an id from another project is a 404. Reads need a login, writes
need the modify-targets permission and the CSRF token.

| Endpoint | |
| --- | --- |
| `GET /api/remediation/?project=&status=` | list one tab |
| `POST /api/remediation/create/` | `project, title, message, due_date, issues[], assignee, emails[]` |
| `GET /api/remediation/detail/?project=&id=` | items, impact, messages, timeline |
| `POST /api/remediation/status/` | `project, id, status` (completed, archived, active) |
| `POST /api/remediation/message/` | `project, id, text` |
| `GET /api/members/?project=` | usernames who can be approver or assignee |
| `GET /api/waivers/?project=` | `{current, past}` |
| `POST /api/action/waiver/decide/` | `project, waiver_id, approve` |
| `POST /api/action/waiver/revoke/` | `project, waiver_id` |

MCP read tools: `list_remediation_requests`, `get_remediation_request` (titles, messages and notes are wrapped as
untrusted text).

## Notes

Plain-text notes (2000 characters, escaped everywhere) can be left on a remediation request, a waiver (Waivers page,
Notes link) and an issue. They are append-only: no edit, and only the author can delete their own. Notes older than
this feature (issue notes, request messages) show in the same timeline, read-only. A new note raises one project
in-app notification naming the assignee, requester, waiver owner or approver (never the note text). Each user may add
30 notes an hour (shared cache counter; it fails closed when the cache is down).

- REST: `GET /api/notes/?project=&type=request|waiver|issue&id=`, `POST /api/notes/create/` (`project,type,id,body`),
  `POST /api/notes/delete/` (`project,note_id`). Another project's ids are 404.
- MCP: `list_notes(project, target_type, target_id)`, text wrapped as untrusted.

## Ignoring a finding

On a vulnerability finding's detail page, Ignore (with a reason) hides it from the Issues list and its counts; the
Ignored chip lists them and Mark as active reverses it. Ignoring never changes the score; waive the issue for that.
Checks cannot be ignored, only waived.
