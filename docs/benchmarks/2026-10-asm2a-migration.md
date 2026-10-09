# ASM 2a Stage 1: migration 0007_migrate_to_assets on the 0A benchmark seed

- Commit validated: `41fc370653b9169f5fa53a3370f6aa5ec897fc1f` (branch `asm-2a-stage1`)
- Setup: `docker compose down -v`, `make up` (0004..0007 applied on empty DB, Assets=0), `make bench-seed`
  (50 domains / 200,000 subdomains / 50,000 vulns), then `run_all(apps)` run explicitly against the dev stack
  (`docker compose exec web manage.py`; note `make manage` targets the separate test DB, not this stack).

## Results

| Item | Result | Status |
|---|---|---|
| hostname assets vs distinct (project, subdomain name) | 200,000 vs 200,000 | PASS |
| root_domain assets vs Domain count | 50 vs 50 | PASS |
| Vulnerabilities with asset / total | 50,000 / 50,000 | PASS |
| Total assets | 200,050 | - |
| `run_all` runtime on seed (first back-fill) | 662.5 s | recorded |
| Idempotency (second `run_all`) | 200,050 -> 200,050, "idempotent" (155.5 s) | PASS |
| Reverse (`migrate startScan 0006`, 30 s) | Assets 0, vulns-with-asset 0; 50,000 vulns and 200,000 subdomains intact | PASS |
| Re-apply (`migrate startScan 0007`, 636 s) | Assets 200,050, vulns-with-asset 50,000 | PASS |
| `make test` | 124 tests OK | PASS |
| `makemigrations --check --dry-run` | "No changes detected" | PASS |

## Notes
- Back-fill throughput is about 300 assets/s (662 s for 200k subdomains + 50k vulns). Acceptable as a one-time
  upgrade migration; a no-op rerun still costs 155 s, so it should not be run routinely.
- Seed contains no endpoints-driven assets in this measurement beyond what `run_all` derives; counts above are
  from the actual run.
