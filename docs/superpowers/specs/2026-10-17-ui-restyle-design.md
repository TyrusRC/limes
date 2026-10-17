# Flat UI restyle

Status: approved by the user on 2026-10-17.
- They chose the direction: "clone upguard ui style + new our style flat not use old reference rengine ui".
- They reviewed the mockup in `2026-10-17-ui-restyle-mockup/` and said "continue, redesign then merge to main".
- They picked the logo: the plain lime slice, committed as `web/static/img/logo.svg`.
- They asked: "apply ui change and layout to localhost to test", meaning each stage is deployed to the test instance.

Everything not listed above is my call.

## Intent

Limes still wears the admin theme it inherited from the reNgine fork: a horizontal top menu, cyan accents, heavy cards and the old hacker logo. The user wants the product to look like an UpGuard-class EASM tool. That means calm, flat and data-first, with its own lime identity, so it reads as a product and not a fork.

## Goals

- **One stylesheet** of our own, `web/static/limes/limes.css`. It is built on design tokens, which are CSS custom properties taken from the mockup's `style.css`. It replaces the inherited theme files `assets/css/app.min.css`, `app-dark.min.css` and `bootstrap/bootstrap-dark.min.css`. It restyles Bootstrap 5.1's components flat, so the ~70 existing templates change look without being rewritten:
  - cards, tables and DataTables;
  - buttons, badges, forms, modals, tabs, dropdowns and alerts;
  - SweetAlert2 and Snackbar.
- **The look,** following the mockup:
  - light grey app background; white cards with 1px borders and no shadows;
  - Inter for text and JetBrains Mono for IPs, hashes and check ids;
  - lime brand colours (#2E8B3E primary, #B5E04A accent); severity colours as solid, tint and text, in both themes.
- **Light by default, dark via `data-theme="dark"` on `<html>`.**
  - The existing `localStorage['limes-theme']` key is kept. When it is unset, `prefers-color-scheme` decides.
  - The theme is set before first paint, so the page never flashes.
- **The app shell is rebuilt to match the mockup:**
  - **Left sidebar.** Logo and wordmark at the top. Grouped links, with every link the current top menu has and the same permission checks:
    - Monitor: Overview, Issues, Assets, Subdomains, Endpoints, Vulnerabilities.
    - Operate: Targets, Organizations, Scan History, Subscans, Scheduled Scans, Recon Notes.
    - Configure (only the links the user may open): Scan Engines, Wordlists, Interesting Lookup, Proxies, Tool Settings, API Vault, LLM Toolkit, Report Settings, Notification Settings, Limes Settings.
    - On narrow screens the sidebar collapses to a toggle.
  - **Top bar:** project switcher (the existing project list, with a link to Projects), theme toggle, the existing notifications, the existing user menu.
  - **Login page:** the logo, wordmark and a flat card.
- **Pages built to the mockup:**
  - **Overview** (`dashboard/index.html`): score gauge with grade and "raw N before waivers", 30-day trend, attack-surface counts, severity tiles, riskiest assets, recent changes. It uses data `dashboard/stats.py` already provides. A tile whose data doesn't exist is left out; no data is invented.
  - **Issues:** filter bar, severity pills, waiver badges, forecast banner, two-column modal.
  - **Assets:** the same table and filter treatment.
- **Fonts are self-hosted** as woff2 under `web/static/limes/fonts/` (Inter and JetBrains Mono, both under the SIL OFL, with the licence files committed). Limes is self-hosted and may run offline, so pages make no Google Fonts or other new third-party requests.

## Non-goals

- **No new features, even where the mockup shows them:** global search, "Create ticket", "Waive selected" (bulk waive) and "Export CSV". The mockup's "Run scan" and "Export report" buttons appear only where the action already exists.
- No change to APIs, models or what a permission allows.
- No JS framework or build step. jQuery, Bootstrap 5.1 JS and DataTables stay.
- No hand rewrite of every template. Pages other than the shell, Overview, Issues, Assets and login get the new look through the stylesheet. Their markup changes only where the sweep finds something broken.

## Anti-goals

- **A page that worked before and is broken after:** layout collapse, invisible text, a dead control, or a new console error. Every route is swept in both themes.
- **A navigation link that disappears,** or that shows to a user who couldn't open it before.
- **Weaker escaping in rewritten templates or JS.** Attacker-influenced text (finding names, hostnames, titles, banners) stays escaped. No `innerHTML` or `.html()` with unescaped data.
- **Text that fails WCAG AA contrast** in either theme, and focus that isn't visible.
- **Score grades in the UI that disagree with `limes/scoring.py`.** Grade bands and colours come from the score payload, never from mockup placeholders.

## Design (my calls)

- **Load order in `base.html`:** `bootstrap.min.css`, then `icons.min.css` (the Material Design Icons used across templates), the plugin CSS, DataTables CSS, `limes.css` and finally `custom.css`, which is trimmed of rules `limes.css` supersedes.
- **`app.min.js`** is removed if nothing outside the old shell needs it. The builder checks; if it stays, it is noted.
- **Tokens:** names copied from the mockup's `style.css`. Bootstrap's own CSS variables (`--bs-body-bg`, `--bs-primary`, …) are mapped onto the tokens so Bootstrap components follow the theme.
- **Score gauge:** an inline SVG arc rendered by the template from the score value. The trend is the existing chart library restyled; if there is none on the page, a small inline SVG sparkline.
- **Test instance:** after each stage lands, the branch is deployed to the local test instance (https://100.118.249.73, compose project `limes-test`, existing volumes kept) for the user to click through.

## Left to the builder

- Exact spacing, icon choices for nav items, the collapse breakpoint, and how each secondary page's oddities are fixed during the sweep.
