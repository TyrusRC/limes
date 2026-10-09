# Phase 0B end-to-end pipeline check

Base commit: `63387976` (plus the three fixes below, committed with this doc).
Host: 10 CPUs, 19 GB RAM (WSL2). Target: local `labtarget` (nginx:1.27-alpine, alias `lab.limes.test`) only.
Engine: `profile=normal`; stages subdomain_discovery(subfinder+amass), http_crawl, port_scan(naabu :80), fetch_url(katana+gau), vulnerability_scan(assay), screenshot.

## 1. Tools in the rebuilt image (`limes-next:local`, 6.08 GB)

```
amass v5.1.1 (no `version` subcommand in v5; banner shows version)
subfinder v2.16.0 | dnsx 1.3.1 | naabu 2.6.1 | httpx (/go/bin) v1.12.0
katana v1.8.0 | nuclei engine v3.11.1 | gau 2.2.4
assay dev (commit: none) | mantis 0.1.0 | opengrep 1.30.1
gospider / dalfox / ffuf / eyewitness / gf: absent
```
Note: `httpx` on PATH is `/usr/local/bin/httpx` (the Python httpx CLI) and shadows `/go/bin/httpx`; the code calls `/go/bin/httpx` by absolute path so the pipeline is unaffected.

## 2. Scan result (scan #144, final run)

Final `scan_status` = 2 (SUCCESS), reached in ~32 min. Not stuck.

| stage | ScanActivity status |
|---|---|
| subdomain_discovery | SUCCESS (subfinder + amass ran; 0 subdomains on bare nginx) |
| http_crawl | SUCCESS |
| port_scan | SUCCESS (naabu: no open ports found, nmap skipped) |
| fetch_url | SUCCESS (katana + gau ran: raw_katana.txt / raw_gau.txt present) |
| vulnerability_scan | SUCCESS (assay, ~30 min on `--profile normal`) |
| screenshot | SUCCESS (task returns cleanly; see section 6) |

Result: 1 subdomain, 1 endpoint, 25 vulnerabilities. code_audit: `code_artifacts.json` is `{}` (bare nginx serves no JS), so the stage skips by design; no activity row is created for it.

## 3. No removed tools
No Command row or `commands.txt` line references EyeWitness/gf/ctfr/sublist3r/dalfox/crlfuzz/s3scanner (0 matches). No missing-binary errors in worker logs.
Only `run_command`/httpx calls create Command rows; amass, katana, gau and assay go through `commands.run` without a recorder, so they are evidenced by output files and the live process list, e.g.
`assay scan -l .../assay_targets.txt --profile normal --config .../assay_config.yaml --output-dir .../assay --json`.

## 4. assay + mantis
- assay: 25 Vulnerability rows, all `source='assay'`.
- mantis: not triggered by the scan (no JS artifacts on nginx). Direct smoke on the image: `mantis.audit_dir('/tmp/ca', packs=['secrets','web'])` on a JS file with an AWS key returned 1 finding (`secret-aws-access-key-id`).

## 5. Destructive flags
grep of commands.txt, Command rows, and the assay process argv for `--h2-reset --h2-continuation --h2-madeyoureset --redos --mass-assign --proto-pollution-server --rate-limit`: 0 matches.

## 6. Secret redaction
Domain header `X-Api-Token: SEKRET_E2E_TOKEN_123` (secret, Fernet-stored) + `X-Plain`.
Scan #144: literal absent from Command rows, `commands.txt`, all result files (`grep -rl` rc=1), all container logs, and all 25 Vulnerability rows.
**Gap found and fixed during this task:** assay echoes the raw request (including secret headers) into `assay-report.json`; scans #142/#143 leaked the value into that file and into 6 Vulnerability rows (request/curl fields). Fixed by `commands.redact_obj` applied to the parsed report before it is rewritten to disk and parsed (test added). Verified clean on #144.

## 7. Screenshot (known deferred follow-up)
`httpx -ss` exits 1 quickly (no hang): it downloads Chromium into `/root/.cache/rod` and then fails with
`libnss3.so: cannot open shared object file` (missing system libs). The screenshot task logs `httpx screenshot exited with 1` and finishes cleanly; the scan is not blocked. The downloaded browser is not persisted across container recreation.

## Bugs found and fixed (all blocked a scan reaching SUCCESS)
1. `http_crawl` crashed on httpx 1.12 output: `host` is now the hostname, the IP is `host_ip` (`save_ip_address` returned None -> `ip.address` AttributeError; every scan failed in `initiate_scan`). Likely also the cause of 0A's `failed: 20`.
2. `LimesTask.write_results` did `f.write(int)` for tasks returning a count (vulnerability_scan) -> TypeError, ChordError, activity stuck at RUNNING. Now `str(self.result)`.
3. assay report leaked secret header values (section 6).

## Notes
- assay `--profile normal` takes its full internal 30 min timeout on a single bare-nginx URL (idle on OAST connections); budget scans accordingly.
- Default fixtures (`web/fixtures/default_scan_engines.yaml`) still list removed tools in engine YAML; not touched here.
