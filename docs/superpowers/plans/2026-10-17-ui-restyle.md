# Flat UI Restyle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the inherited admin theme with Limes's own flat, token-based look (light and dark), with a left-sidebar shell and the Overview, Issues and Assets pages rebuilt to the approved mockup.

**Architecture:** One stylesheet, `web/static/limes/limes.css`, restyles Bootstrap 5.1, DataTables and plugin components through CSS custom properties, so most templates change look untouched. The shell (`base.html` plus `_items`) and the three key pages are rebuilt by hand. A final sweep renders every route in both themes and fixes what breaks.

**Tech Stack:** Django 3.2 templates, Bootstrap 5.1 (CSS and JS), jQuery, DataTables 1.13, Material Design Icons, self-hosted Inter and JetBrains Mono, puppeteer-core with `/usr/bin/chromium` for the UI checks.

**Spec:** `docs/superpowers/specs/2026-10-17-ui-restyle-design.md`, with the mockup in `docs/superpowers/specs/2026-10-17-ui-restyle-mockup/`. Read `style.css` there for the token names and values; the PNGs show the target.

## Global Constraints

- Brand: primary `#2E8B3E`, accent `#B5E04A`, tint `#F3FBE3`, ink `#16261B`; critical `#E5484D`.
- Light is the default. Dark is set by `data-theme="dark"` on `<html>`. The preference persists in `localStorage['limes-theme']`; when it is unset, `prefers-color-scheme` decides. The theme is applied before first paint.
- No new third-party requests. Fonts are self-hosted woff2, with their OFL licence files.
- Do not build the mockup's features that don't exist: search, Create ticket, Waive selected, Export CSV.
- Every link in today's `_items/top_nav.html` stays reachable, under the same `user|can:'…'` checks.
- Attacker-influenced text stays escaped. No `innerHTML` or `.html()` with unescaped data.
- WCAG AA contrast in both themes, and a visible focus ring.
- Grades and colours come from the score payload (`limes/scoring.py`), never from mockup placeholders.
- PDF report templates (weasyprint) must not load `limes.css` and must render as before.
- Commits: repo identity, no AI attribution, no `--no-verify`.

## Review Focus

1. **Dark mode on DataTables-heavy pages** (subdomains, endpoints, vulnerabilities): the header, pagination, the processing overlay and the search input must all be readable. Covered by the Task 5 sweep, both themes.
2. **Long hostnames, URLs and banners in tables and cards:** they wrap or truncate with a title, never pushing the page sideways. Task 1 adds `.text-break`-style defaults to table cells; the Task 5 sweep checks the vulnerabilities page.
3. **Navigation permission parity:** an auditor or penetration-tester user sees exactly the links they saw before. Task 2 adds a Django test that renders the sidebar for users with and without each permission.
4. **Plugin pop-ups** (SweetAlert2, Snackbar, Bootstrap modals and dropdowns) follow the theme in dark. Task 1 styles them; the Task 5 sweep opens one modal per page family.
5. **PDF reports unaffected:** Task 5 renders one report PDF and compares it to `main` visually.

---

### Task 1: Tokens, fonts, theme switch and component styles

**Files:**
- Create:
  - `web/static/limes/limes.css`;
  - `web/static/limes/theme.js` (tiny: apply the theme before paint, toggle handler);
  - `web/static/limes/fonts/` (Inter 400/500/600/700, JetBrains Mono 400/500 as woff2, plus `OFL.txt` for each).
- Modify:
  - `web/templates/base/base.html`: the load order from the spec. Drop `app.min.css`, `app-dark.min.css` and `bootstrap-dark.min.css`. Replace the old dark-mode toggle script with `theme.js` loaded in `<head>`.
  - `web/static/custom/custom.css`: remove rules `limes.css` supersedes.

- [ ] **Step 1: Implement.**
  - Tokens are copied from the mockup's `style.css`. Bootstrap's CSS variables and the component selectors are mapped onto them:
    - `.card`, `.table` and DataTables (`.dataTables_wrapper`, pagination, processing);
    - `.btn-*`, `.badge`, `.form-control`, `.form-select`, `.modal`, `.nav-tabs`, `.dropdown-menu`, `.alert`;
    - `.swal2-*`, `.snackbar-container`.
  - Add severity pill classes `sev-critical`, `sev-high`, `sev-medium`, `sev-low` and `sev-info`. Map the existing severity badge classes onto the same colours.
  - Table cells get `overflow-wrap: anywhere`.
  - Fonts are fetched once from their upstream releases and committed.
- [ ] **Step 2: Verify.**
  - Run the template check (`scratchpad/tpl.sh`) and the full suite.
  - A puppeteer script screenshots Overview, Subdomains, Vulnerabilities and one settings page in both themes, and reports any console error.
  - Reload in dark: there is no light flash (the theme attribute is present in the HTML before CSS applies).
  - The network log shows no request to `fonts.googleapis.com` or any new host.
- [ ] **Step 3: Commit** "Replace the inherited theme with Limes design tokens".

### Task 2: App shell — sidebar, top bar, login

**Files:**
- Create: `web/templates/base/_items/sidebar.html`.
- Modify: `web/templates/base/base.html` (layout wrapper), `web/templates/base/_items/top_bar.html`, `web/templates/base/login.html`; remove the `top_nav.html` include and the file.
- Test: `web/tests/core/test_navigation.py`.

**Interfaces:**
- Consumes: Task 1 tokens and classes.
- Produces: the layout classes `.l-app`, `.l-sidebar`, `.l-topbar` and `.l-main` that page templates sit in. Page content blocks keep their current block names.

- [ ] **Step 1: Write the failing test.**
  - `test_sidebar_links_follow_permissions`: render the dashboard as a superuser and assert every one of today's `top_nav.html` URLs is present.
  - Render as an auditor-role user and assert that each `can:` gated URL (`scan_engine_index`, `wordlist_list`, `interesting_lookup`, `proxy_settings`, `api_vault`, `report_settings`, `limes_settings`, `notification_settings`) is present exactly when the user has that permission.
  - `issues` and `assets` are present for both users.
- [ ] **Step 2:** Run it: it fails, because `sidebar.html` doesn't exist and the links are still in `top_nav`.
- [ ] **Step 3: Implement the sidebar,** grouped as in the spec. Active-link highlighting comes from the request's URL name.
  - On viewports narrower than 992px the sidebar becomes an off-canvas panel, opened by a top-bar button (Bootstrap offcanvas).
  - The top bar holds the project switcher (existing project dropdown plus a "Projects" link to `list_projects`), the theme toggle, the existing notifications and the existing user menu.
  - The login page shows `logo.svg`, the "limes" wordmark (HTML text in Inter) and a flat card.
  - Remove `app.min.js` if no remaining template needs it. `grep` for the functions it provides; note the result in the report.
- [ ] **Step 4: Run the test and the full suite.** Then the real UI as superuser and as auditor:
  - every link opens;
  - the mobile width (390px) toggle works;
  - there are no console errors.
- [ ] **Step 5: Commit** "Move navigation to a left sidebar shell".

### Task 3: Overview page

**Files:** Modify `web/dashboard/templates/dashboard/index.html` and its page JS. `dashboard/stats.py` changes only to expose data that already exists.

- [ ] **Step 1: Implement the mockup's Overview** from `asm_stats`:
  - the gauge, an SVG arc from `score` out of 950, with the grade and "raw N before waivers · M waived" only when `raw_score != score`;
  - the 30-day trend from the existing snapshot series;
  - attack-surface counts;
  - severity tiles;
  - riskiest assets;
  - recent changes.
  - Leave out any tile `asm_stats` has no data for.
  - With no score yet, show the existing "not assessed" state.
- [ ] **Step 2: Verify.**
  - Run the template check and the dashboard tests.
  - In the real UI, check both themes with data and with an empty project.
  - An asset named `<img src=x onerror=alert(1)>` renders as text in riskiest assets and recent changes.
- [ ] **Step 3: Commit** "Rebuild the Overview page in the flat layout".

### Task 4: Issues and Assets pages

**Files:** Modify `web/startScan/templates/startScan/issues.html`, `web/static/custom/issues.js`, the Assets template and `web/static/custom/asset.js`.

- [ ] **Step 1: Restyle to the mockup.**
  - The filter bar becomes a card.
  - Severity uses `sev-*` pills.
  - Waiver badges: accepted risk in indigo, false positive in grey, expired as an outline.
  - Forecast banner styling.
  - The issue modal has two columns (waiver on the left, notes on the right) and stacks below 992px.
  - Assets get the same table, filter and modal treatment.
  - Keep every existing behaviour and escape helper. Do not add the mockup's bulk or ticket buttons.
- [ ] **Step 2: Verify.**
  - `node --check` both JS files, then the full suite.
  - In the real UI, in both themes, rerun the waivers check from the waivers plan's Task 5: the XSS finding name renders as text; waive, revoke, note and forecast all work; an auditor gets no controls.
  - On Assets: open a modal, and the risk table marks waived rows.
- [ ] **Step 3: Commit** "Restyle the Issues and Assets pages".

### Task 5: Every-route sweep and cleanup

**Files:**
- Create: the scratch sweep script (not committed).
- Modify: whichever templates and CSS the sweep finds broken.
- Delete: `web/static/assets/css/app.min.css`, `app-dark.min.css` and `web/static/bootstrap/bootstrap-dark.min.css`, if nothing references them.

- [ ] **Step 1: Sweep.**
  - Enumerate every non-API URL pattern; fill path args from seeded objects (project, target, scan, subdomain, engine, organization).
  - Load each in light and dark at 1440px, and the shell at 390px.
  - Record the status, console errors and screenshots.
  - Fix each layout break, unreadable text or dead control.
  - Open one modal per page family.
- [ ] **Step 2: Clean up.**
  - Delete the unreferenced theme files (`git grep` proves no references).
  - Render one PDF report: it matches `main` (no `limes.css`).
  - Run a contrast check on the token pairs (text on bg, muted on bg, every pill) in both themes; each must be at least 4.5:1, or 3:1 for large text.
- [ ] **Step 3: Verify.** Template check, full suite, sweep rerun clean (every route 200 or an expected redirect, zero console errors).
- [ ] **Step 4: Commit** "Fix restyle regressions found by the route sweep and drop the old theme".
