# ASM A1 pipeline validation (2026-10-08)

Validated commit: `7dfb8281` (branch `asm-a1`, base of this doc commit).

## Invariants (test DB)

- Targeted modules (`test_no_joins`, `test_celery_config`, `test_inventory_writes`, `test_scan_mode`, `test_asset_models`): `Ran 48 tests ... OK`.
- Full `make test`: `Ran 158 tests ... OK`.
- `makemigrations --check --dry-run`: `No changes detected` (only the pre-existing `EndPoint.techs` W340 warning).
- `blocking_tasks()` (from `tests/core/test_no_joins.py`) called directly: `[]`.

## E2E asm run (dev stack, clean volumes, migrations 0004..0008 applied)

Path used: the real Celery path. `initiate_scan(scan_history_id, domain_id, engine_id, scan_mode='asm')`
was called synchronously in `manage.py shell` on the dev `web` container; the resulting chain
(`subdomain_discovery` -> `screenshot` -> `report`) was executed by the real workers.
Engine: `subdomain_discovery` (subfinder) + `screenshot`; domain `lab.limes.test` (project `a1val`),
`imported_subdomains=[a.lab..., b.lab...]`. Seeded with a single domain, not `make bench-seed`.

| Assertion | Result |
|---|---|
| `ScanRun(mode='asm')` created | yes: 1 run, mode `asm`, root_asset=1, finished status 2 |
| Workflow task set | `Running Celery workflow with 3 tasks` = subdomain_discovery, screenshot, report |
| `ScanJob` stages | `discovery` x1, `probe` x2 (http_crawl in initiate_scan + screenshot), all status 2 |
| Scanner stages (ports/crawl/dast/code) | none: 0 ScanJobs |
| Assets | 2: `root_domain` lab.limes.test, `hostname` lab.limes.test (parent = root); both `active`, missed_count 0 |
| IP assets | 0 (lab host does not resolve, so the probe returned no address) |
| Legacy history | 1 `Subdomain` row still written alongside |
| `ScanHistory` | status 2 (success) |

## Notes

- The `imported_subdomains` were not persisted as `Subdomain`/`Asset` rows (legacy count is 1, the root only). This is existing `save_imported_subdomains` behaviour, not exercised by A1; not investigated further.
- The lab host is unresolvable and discovery is offline-limited, so the Asset population is minimal (root + root hostname); ip-kind assets and the active->missing lifecycle are covered by unit tests, not this e2e.
- The worktree `.env` had to be extended with the new compose vars (`PGBOUNCER_TAG` etc., from `.env.example`) before `make up` would start.
