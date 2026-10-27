# Reports

The **Reports** page (sidebar, under Monitor) has the executive summary, CSV exports and recurring reports.

## Executive summary

`/<project>/reports/summary` is one page: the headline score, grade and trend, a plain-language headline (templated
sentences from the data, no model), the score by category, the 100 costliest open issues with their first-detected
date, remediation progress (fixed against opened), what changed, per-tag scores, and exposure, certificate,
technology, discovery, coverage and brand highlights. Filter by period (30, 90 or 365 days) and by tag. With a tag the
score, open issues, top risks, remediation and tag section cover the tagged assets; the rest stays project-wide and the
page says so.

Provisional categories (IP reputation, data leakage) and the lookalike/brand figures are marked "Provisional, not
scored": they list issues but never move the headline score.

Use **Print or save as PDF** in the browser. The print stylesheet targets A4 and hides the navigation. No PDF library
is installed on purpose.

## Templates and the board summary

The **Templates** tab saves, per project, a section choice (score and history, category breakdown, top risks, new and
resolved changes, waivers, remediation status, tags and assets summary) and plain-text commentary (up to 2,000
characters, shown escaped with its line breaks). Open one with `/<project>/reports/summary?template=<id>`, pick it
when generating, or attach it to a recurring report (a template of another project is rejected). The figures are the
same as the live pages: waivers use the scoring's own active-waiver rule, and the tag filter applies as before.

The **Board summary** layout is one page: grade and trend, the top 5 risks, what changed, and "What we need decided"
(the commentary). Print or save as PDF as usual.

## Exports

`/<project>/reports/export/issues.csv` and `.../assets.csv` (both accept `?tag=`) are plain CSV. Assets carry their tags.
Any text cell a spreadsheet would run as a formula (starting with `=`, `+`, `-`, `@`, tab, CR or LF) is stored as text
by prefixing an apostrophe. A file holds at most 50,000 rows; a cut file ends with a `# truncated` line and sends
`X-Limes-Truncated: 1`. There is no XLSX: `openpyxl` is not a dependency.

## Recurring reports

A schedule has a name, frequency (weekly, monthly, quarterly), a UTC time (weekday for weekly; day 1 to 28 for monthly
and quarterly, the quarterly one in the quarter's first month), an optional tag, delivery and up to 20 recipients. A
report covers 30 days (weekly, monthly) or 90 days (quarterly). Changing or creating schedules needs the
scan-configuration permission; reading and downloading needs only a login.

The beat task `generate_due_reports` runs every 15 minutes. Each period (`2026-W44`, `2026-10`, `2026-Q4`) yields one
report per schedule: the period key is unique in the database, so re-runs and racing workers never duplicate. Only the
current period is generated; a schedule created after its moment this period starts with the next one. Set
`LIMES_REPORTS_ENABLED=false` to stop the task (manual generation and existing reports stay).

Reports are self-contained HTML (inline CSS, no script, no external URL, every value escaped) under
`$LIMES_RESULTS/reports/<project id>/<random>.html`, directory 0700 and file 0600. They are never under a static or
media URL: the only way out is the download view, which is project-scoped (another project's id is a 404), accepts only
names the app wrote, refuses symlinks, and answers as an attachment with a restrictive CSP.

### Email

With delivery "in-platform and email" each recipient gets its own short message (headline, score, a path to the Reports
page). The report itself is never attached. Limes uses Django's email settings (`EMAIL_BACKEND`, `EMAIL_HOST`, ...); if
the backend is SMTP and `EMAIL_HOST` is empty or `localhost`, delivery is recorded as "Email not configured" and the
in-platform copy is still made. A send failure is recorded ("Email failed") without the error text and never loses
the report.
