# Certificate watch (opt-in)

`ct-watch` runs a pinned certspotter (v0.25.0, built in the Dockerfile `gotools` stage) against the public CT logs and
feeds matching certificates into Limes within seconds. It is off by default: the compose service sits in the
`realtime` profile, and the supervisor idles unless `LIMES_CT_WATCH=true` and `LIMES_CONTINUOUS_SCANS` are both on.

Enable: set `LIMES_CT_WATCH=true` in `.env`, then `make up REALTIME=1`. Egress goes through `HTTPS_PROXY` when set.
Health: `docker compose --profile realtime exec ct-watch python3 manage.py ct_watch --health`.

Files live under `/var/lib/ct-watch` (the `ct_state` volume): `state/` (certspotter), `spool/`, `watchlist.txt`,
`last.json` (last ingest and match times, kept across restarts).

## Security model

- The container publishes no ports, drops all capabilities, sets `no-new-privileges`, runs with a read-only root
  filesystem (tmpfs `/tmp`), a PID limit and a memory limit.
- The supervisor (`manage.py ct_watch`) uses the same image and `.env` as the app, so it holds the database and Redis
  credentials and runs as root. certspotter is its child process and receives only an allowlist of variables
  (`PATH`, `TMPDIR`, `SSL_CERT_FILE`, `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` and lowercase forms, plus `HOME`, the spool
  path and a read-only config dir so no `hooks.d` is run from the volume). It is started from an argv list, never a shell.
- Certificate data is hostile. The hook (stdlib only, isolated interpreter) validates the hash before using it as a file
  name, refuses links and files over 256 KiB, and writes atomically. The supervisor never follows links in the spool and
  checks names and sizes before reading.
- Upgrade path: run certspotter in its own non-root container that shares only the spool volume and has no `env_file`.

## Operator procedure (not run by the build or the tests)

Both steps contact the live CT ecosystem. Get the owner's explicit go-ahead before doing either.

1. Bandwidth measurement (24 h). The 157 GB/day figure is inferred, not measured. The watcher moves no traffic unless
   `LIMES_CONTINUOUS_SCANS` is on and at least one owned root exists (otherwise the watchlist is empty and it idles), so
   check that first or the measurement records zero: the heartbeat state must read `running`, not `idle` or `off`.
   Start it with `make up REALTIME=1`, then read the container's inbound counters before and after 24 h, for example
   `docker stats --no-stream $(docker compose --profile realtime ps -q ct-watch)` (network I/O column) or the host
   interface counters. The container is named `<compose project>-ct-watch-1`; `docker compose --profile realtime ps`
   shows it. Decide whether the link and any data cap allow it. Stop with `docker compose --profile realtime stop ct-watch`.
2. End-to-end check with a test certificate. A staging CA or a private CA does not publish to the public CT logs, so it
   proves nothing. The only working path is a publicly trusted certificate for a name you control under an owned root.
   Issuing it makes that name public in CT permanently, so pick a throwaway label you are content to publish. Then
   confirm a certificate sighting appears and the heartbeat (`limes:ct:watch` in Redis) shows `last_match_at`.
   Never issue certificates for names you do not own.
