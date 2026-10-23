# Certificate watch (opt-in)

`ct-watch` runs a pinned certspotter (v0.25.0, built in the Dockerfile `gotools` stage) against the public CT logs and
feeds matching certificates into Limes within seconds. It is off by default: the compose service sits in the
`realtime` profile, and the supervisor idles unless `LIMES_CT_WATCH=true` and `LIMES_CONTINUOUS_SCANS` are both on.

Enable: set `LIMES_CT_WATCH=true` in `.env`, then `make up REALTIME=1`. The container publishes no ports, drops all
capabilities and keeps its state in the `ct_state` volume. The certspotter child gets a minimal environment (no
database or Redis credentials). Health: `docker compose exec ct-watch python3 manage.py ct_watch --health`.

## Operator procedure (not run by the build or the tests)

These two steps contact the live CT logs or the public CA ecosystem, so they are left to the operator.

1. Bandwidth measurement (24 h). The 157 GB/day figure is inferred, not measured. Start the watcher on a host whose
   inbound traffic you can read (`docker stats ct-watch`, or the interface counters), leave it for 24 h, and record
   the inbound total. Decide whether the link and any data cap allow it before leaving it on. Stop with
   `docker compose --profile realtime stop ct-watch`.
2. End-to-end check with a test certificate. Add a root you own (for example `ct-test.example.org`) to a project,
   issue a certificate for a name under it from a CA you control or a staging CA (for example the Let's Encrypt
   staging environment, if its log is watched), and confirm that a certificate sighting appears and the heartbeat
   (`limes:ct:watch` in Redis) shows `last_match_at`. Do not issue certificates for names you do not own.
