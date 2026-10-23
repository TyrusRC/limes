# UpGuard Breach Risk (ex-BreachSight): UI notes from PUBLIC help docs
Research date 2026-10-23. Public pages only; no login, no forms. Help articles are mostly text with unreadable screenshots, so layout detail is thinner than the real UI. "(inferred)" marks my guesses. The product was renamed BreachSight -> "Breach Risk"; old URLs still say breachsight.
Index: https://help.upguard.com/en/upguard-breach-risk  |  Platform index: https://help.upguard.com/en/the-upguard-platform

## 1. Navigation / main sections
- Left nav (sidebar), per Attack Surface Posture article (https://help.upguard.com/en/attack-surface-posture): "Breach Risk icon in the left navigation" -> Risk Profile. Header has "Settings cog (top-right)" (https://help.upguard.com/en/articles/4995221-how-to-create-custom-notifications) and a "Current Portfolio" dropdown in the page header (https://help.upguard.com/en/articles/7054632-how-to-use-asset-portfolios-to-segment-your-domains).
- Breach Risk help sections = roughly its pages: Executive Summary Report, Risk Profile, Domains, IP addresses, Remediation, Typosquatting, Subsidiaries, Vulnerabilities, Identity breaches, Risk waivers, Threat Monitoring (index URL above). Separate products: Vendor Risk, Data Leaks, Trust Exchange, User Risk, Risk Automations; platform-level: Home, Reports, Settings, Incidents & News.
- Home: feed with "All activity" and "My tasks" views, "Your tasks" count, notification cards (title, timestamp, description, action button, star, X dismiss), "Previously seen", "You're all caught up" (https://help.upguard.com/en/articles/4995465-how-to-manage-your-home-screen).
- Features page groups by Monitor / Remediate / Manage (https://www.upguard.com/product/breach-risk/features): Security ratings, Custom notifications, Domains & IPs, Asset Portfolios, Vulnerabilities, Typosquatting, Identity breaches, Remediation workflows/planner, Risk waivers, Templates, Executive reporting, Collaboration notes, Subsidiaries, Audit log, Scheduled reports, integrations.
- Product page marketing labels: External Attack Surface Management ("daily scans", hidden subdomains, shadow IT, misconfigured cloud), AI Threat Analyst, Data Leak Detection, Dark Web Monitoring, Brand Protection, Executive Reporting (https://www.upguard.com/product/breach-risk).

## 2. Risk Profile / overview
Source: https://help.upguard.com/en/articles/4491787-what-is-your-risk-profile
- Path: Breach Risk > Risk Profile. Security rating with history over selectable period (1 / 3 / 12 months per https://help.upguard.com/en/articles/4594330-how-to-view-changes-in-your-attack-surface-over-time). Toggle "internal vs public rating" (internal excludes waived risks).
- Score: 0-950; grades A 801-950, B 601-800, C 401-600, D 201-400, F 0-200 (https://help.upguard.com/en/articles/3765184-how-are-upguard-s-security-ratings-calculated).
- 10 categories with penalty weights: IP/domain Reputation 19%, Website 19%, Encryption 17%, Vulnerability Management 13%, Attack Surface 11%, Network 8%, Email 7%, Data Leakage 3%, DNS 2%, Operational Risk 1% (same URL). Executive Summary says each category has description, weighting, rating, risk breakdown.
- Graph interaction: click a point = single date, drag = range (darker); "View Changes" opens a "changes view" (blue box around graph) with sections: New domains and IPs detected; Domains and IPs removed; Scoring algorithm changes; Risks introduced (detection date, severity, name, risk, category, affected domains); Risks resolved (risk, category, domains protected). "Export" + "Include changes view" -> PDF/Excel.
- "Attack Surface Posture" AI panel (tags "AI", "New"): plain-language posture headline (e.g. "low"), "Top insights" (collapsed; each has "Filter risks" toggle; expanded sections "What was detected" / "Why it matters" / "Recommended action"), filter chip with "Clear insight filter", thumbs up/down "Was this helpful?" (https://help.upguard.com/en/attack-surface-posture).
- Filters: "Apply filters" button -> portfolio, label, finding, severity, more; "Risk category" with subsidiaries.
- Subsidiaries: "Organization and subsidiaries" toggle, rolled-up list (severity, name, risk type, category, number of companies impacted); each entity keeps own score, subsidiary scores don't hit parent.
- Summary counts: NOT specified in docs.
- Provisional risks: new checks added with zero score impact first, title contains "provisional", email on add and on score impact (https://help.upguard.com/en/articles/6708571-what-are-provisional-risks).
- Informational risks: unverifiable findings, shown but never scored (https://help.upguard.com/en/articles/4513857-why-do-some-risks-appear-as-informational).

## 3. Risks list and detail
- Severity wording: critical, high, medium, low (+ informational). Default sort most severe first (risk profile + remediation article https://help.upguard.com/en/articles/5357951-how-to-request-remediation-from-someone-at-your-organization).
- List ("Risk details" section) shows: date first detected, category, number of assets affected, finding/issue, a Status column (e.g. remediation in progress). Exact headers not given.
- Detail view: description, recommended remediation steps, actions to request remediation or waive; per-asset check expands to description, "first detected" date, actual vs expected value (https://help.upguard.com/en/articles/3824996-what-is-upguard-breachsight-s-domains, https://help.upguard.com/en/articles/7872953-how-to-investigate-and-verify-a-risk-finding). "First detected" resets if a risk recurs after a scan that did not show it.
- Bulk/actions: "Manage risks" button -> dropdown (request remediation / waive). Risk selection in the remediation wizard has category selector + search + expandable rows listing domains/IPs.
- Vulnerabilities page (https://help.upguard.com/en/articles/3806262-what-is-upguard-breachsight-s-vulnerabilities-module): columns CVSS (v3, v2 fallback), CVE ID, verified/unverified, "known" label (CISA KEV), EPSS; "Apply filters": Label, Verified status, CVE ID, Software, CVSS severity, EPSS score; search by CVE; "Ignore Vulnerabilities" button, "Ignored" tab, "Mark vulnerabilities as active".
- Grouping by asset/category/first-detected: not described as a toggle; only sort/filter. (gap)

## 4. Assets
- Domains (Breach Risk > Domains): auto-discovered, scanned daily; per domain: security rating, first scanned, last scanned, labels, portfolios. Detail: associated IPs; checks split passed/failed. Tabs: active list and "Inactive" tab. Multi-select checkboxes -> "Edit labels", "Edit portfolios". Add via "Add domain"; export via article https://help.upguard.com/en/articles/5039576-how-to-export-your-domains; rescan icon.
- Active = has an open port or MX record (redirects count); inactive = neither (or wildcard-inherited with HTTP >= 400); inactive scanned monthly, active daily (https://help.upguard.com/en/articles/4169913-what-s-the-difference-between-an-active-and-inactive-domain).
- Add/remove/associate: custom domains for what heuristics missed; "officially associate" (confirm) the domain with your org so new subdomains are discovered and monitored automatically; subdomains otherwise added manually (https://help.upguard.com/en/articles/4267762-options-for-adding-to-your-domains-in-upguard-breachsight). Attribution logic: https://help.upguard.com/en/articles/4535055-how-does-upguard-determine-the-ownership-of-my-or-my-vendor-s-domains (not read).
- Labels: "Add label"/"+" -> modal, "Update labels", "+ Create new label"; removal article exists. Portfolios (groups with access control): Settings > "Domain/IP Management" > Portfolios; default "Default"; new subdomains inherit nearest parent's portfolio; IPs inherit via domains; per-user access full/restricted/none ("Specific portfolios"); "Switch Portfolio"/"Current Portfolio"/"All Portfolios".
- IPs: discovered from DNS + manually added IPs/ranges; address detail: owner, range, country, AS/ASN, associated domains; range detail: owner, country, IP count, detected IPs/domains; filter by services, IP owner, ASN, country; "Owned Ranges" monitored for shadow IT (https://help.upguard.com/en/articles/4786030-how-to-monitor-your-ip-addresses-and-ip-ranges).
- Detail page contents: ports/services ("Port Scanning Services Index"), "Detected Products" article (https://help.upguard.com/en/articles/8663342-what-is-detected-products); certificates, DNS, WHOIS tab layout NOT described (gap; inferred only via the ten categories).

## 5. Remediation / waivers / collaboration
- Remediation page (Breach Risk > Remediation) (https://help.upguard.com/en/articles/3833873-how-to-manage-internal-remediation-requests-with-upguard): list columns Title, risk categories, number of open risks, impacted assets, last updated, status; tabs Active / Completed / Archived; bulk export + archive. Detail: Summary (status, title, deadline, collaborators), Risks (add/remove), "Messages" button (collaborator pane), timeline of events; "Mark as completed", "Reopen".
- Create: "Request remediation" -> select risks -> Next -> recipient email(s), due date, title, message -> Next -> review -> "Submit request"; recipients respond inside UpGuard (no seat needed implied; inferred). Default email template editable under Templates.
- Remediation planner (https://help.upguard.com/en/articles/5489686-how-to-calculate-potential-score-changes-with-the-remediation-planner): "Select risks and assets" step; "Your remediation plan" panel shows live potential score impact; accounts for interaction between findings; recipient also sees it.
- Waivers (https://help.upguard.com/en/articles/3883003-how-to-use-risk-waivers-in-breachsight): "Create risk waiver" on Risk Profile or "Risk Waivers" in sidebar; pick risk; scope all domains/IPs (also covers future assets) or selected; optional approval by someone else (admins nominate approvers, can make mandatory in Settings); public vs private/internal (public ones are visible to Vendor Risk customers and alter the score they see: https://help.upguard.com/en/articles/7065952-how-to-use-public-risk-waivers-in-breachrisk); expiry date with reminder before; expired -> counts again. Waiver list: current and past; change approver, change expiry, cancel; delete supported (release notes via search). Justification/controls text is referred to by the Features page ("with justifications") but the field isn't described in the how-to. Waived risks leave internal score only.
- Notes: "Collaboration notes" on remediation requests, risk waivers, data leaks (features page).
- Progress: request status + timeline; Home "My tasks" (reminders for remediation requests/waiver approvals).

## 6. Notifications
(https://help.upguard.com/en/articles/3883016-what-are-notifications-in-upguard, .../4995221-..., .../4995465-...)
- Types: Activity (rating changes, vendor rating changes, new identity breaches), Tasks (review questionnaires/remediation, approve internal waivers), Audit Log events (admins), Custom notifications (admin-created, org-wide).
- Custom: Settings cog > Custom Notifications > Create Notification; fields: notification type, severity level, assessment timeframe, conditions on tiers/labels/portfolios; options starting "When risks ..."; example "score drops by 10 points within 7 days and has In-Use label".
- Channels: in-app Home feed (default on), email (user toggles in "Manage notifications"), webhook (admin, "Create Integration"), team email, Slack, Jira, Zapier, Teams for data leaks. Per-user: "Manage Notifications" page with in-app/email toggles; dropdown None/My requests/All requests etc. Digests: not mentioned.
- Slack uses Liquid templating (https://help.upguard.com/en/articles/5777453-using-liquid-syntax-to-customize-your-integration, not read).

## 7. Reports
(https://help.upguard.com/en/articles/3883000-what-is-in-the-upguard-breachsight-executive-summary, .../8230473-..., .../6339293-...)
- Executive Summary sections: Overall security rating (+ industry average, risk breakdown); scoring breakdown pop-up; Competitor Analysis (up to 9); Risk category breakdowns (description, weighting, rating, risk breakdown); Geolocation Risk Breakdown (map or table). "Export" button; "Generate report" -> Breach Risk Summary or Detailed.
- Also: Board summary report, custom report templates (custom commentary, selectable sections), subsidiaries report, per-page reports; filter by label.
- Scheduling: Reports page tabs "Generated Reports" and "Recurring reports"; Frequency weekly/monthly/quarterly/annual with start date; PDF or Excel; choose sections; "Report delivery": platform only or email + platform; "Email recipients".

## 8. Settings / integrations
- Settings cog: Domain/IP Management (portfolios), Custom Notifications, Integrations (+ New Integration: Jira Cloud wizard: Triggers -> Name & destination -> Review content (issue type, custom fields, "Test Create Issue") -> Enable/Disable; Slack; email; webhooks; Zapier), Templates, custom branding, users, audit log (filter user/event/time, exportable).
- Roles: Administrator, Standard, Read-Only, custom roles (some plans); module access Full/Read only; portfolio-scoped access. SSO: Azure, Okta, Ping, any SAML. API: risks for account/vendor documented (https://help.upguard.com/en/upguard-api); the API docs site (cyber-risk.upguard.com/api/docs) is a JS app and returned nothing fetchable, so no field names.

## 9. Typosquat, data leak, identity breach (one-liners)
- Typosquatting: watch domains, auto-generated permutations (drop/replace/swap chars), "active" judged by registration, age, DNS records; filter, ignore a permutation, export, takedown request (https://help.upguard.com/en/articles/3824963-what-is-upguard-s-typosquatting-module).
- Data leaks: managed service; findings published, can be closed, notes; GitHub/bucket removal guides; MS Teams notification (https://help.upguard.com/en/upguard-data-leaks).
- Identity breaches: table with Columns button (severity, types of data exposed, date of breach, publish date, employees exposed, VIP count, notification status); detail labels: Breached company name, Breach details, Date of breach, Date published, Total involved, Data exposed, Severity, Notification sent, Employees involved, Breach status, Breach type; severity by data type/amount; can notify affected users in-app (https://help.upguard.com/en/articles/3806295-what-is-upguard-breachsight-s-identity-breaches-module).

## Top 12 ideas for Limes (value x feasibility)
1. Score-history graph with 1/3/12-month toggle and a click/drag "View Changes" panel (new assets, removed assets, risks introduced, risks resolved). Limes already has change alerts, so this is mostly a view.
2. Risk list with severity (critical/high/medium/low/informational), category, affected-asset count, first detected, status; default sort worst first; expandable rows to assets.
3. Risk detail with description, why it matters, remediation steps, expected vs actual value, first detected per asset.
4. "Informational" tier: unverified findings listed but never scored; "provisional" new checks shipped with zero score impact.
5. Waivers: scope (all vs selected assets, incl. future), expiry with reminder, optional approver, internal-only; waived risks drop from score, list of current/past.
6. Remediation request wizard (select risks -> recipient/due date/message -> review) with Active/Completed/Archived tabs, Messages pane, timeline, plus live "potential score impact" panel.
7. Domain list with Active/Inactive tabs (active = open port or MX), bulk Edit labels / Edit portfolios, rescan icon, daily vs monthly scan cadence.
8. Portfolios (default + inheritance by parent domain) and a "Current Portfolio" header switcher filtering every page and export.
9. Confirm/associate flow: explicit "associate with my org" so new subdomains auto-monitor; unconfirmed stay as candidates.
10. Custom notification rules (type, severity, timeframe, label/portfolio conditions) + channels in-app/email/webhook/Slack/Jira; Home feed with All activity / My tasks.
11. Executive summary report + recurring reports (weekly/monthly/quarterly, PDF/Excel, section picker, email recipients).
12. Vulnerabilities page: CVE, CVSS, EPSS, KEV flag, verified filter, Ignore/Ignored tab.

## Gaps the docs don't answer
- Actual score/grade widget visuals, summary count tiles, history chart style (screenshots unreadable).
- Risk list exact column headers, grouping toggles, severity colors; list-level bulk actions beyond waive/remediate.
- Waiver justification field, status values, "kinds" beyond all/selected and public/private; waiver deletion detail.
- Domain/IP list column headers; asset detail tabs (technologies, certificates, DNS, WHOIS); how "confirm" differs per asset; unmonitored IP states.
- Notification event catalogue, digests; Slack/webhook payload schema.
- API field names (docs site is client-rendered); recommend inspecting the public OpenAPI JSON if available.
- Interactive tour is lead-gated and was not used.
