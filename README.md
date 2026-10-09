# Limes

Self-hosted external attack surface management for one organization. Limes keeps an inventory of
the domains, hosts and IPs you own, discovers new ones continuously, and scans them with a fixed,
quiet pipeline: amass + subfinder → dnsx → naabu → nmap → httpx → katana + gau → assay → mantis.

Active testing only ever runs against assets confirmed as owned; everything else gets passive
checks. See [the roadmap](docs/superpowers/specs/2026-10-07-asm-platform-roadmap-design.md).

## Install (Linux, Docker)

```bash
git clone https://github.com/TyrusRC/limes && cd limes
sudo ./install.sh          # -n for non-interactive
```

`install.sh` creates `.env` from `.env.example` with fresh random secrets and memory limits sized
to the host. Review it before continuing, and set `PGBOUNCER_TAG` to a tested
`edoburu/pgbouncer` tag. Compose refuses to start while it is empty.

Limes is then served at `https://<host>` (nginx on 443).

## Common tasks

| Command | What it does |
|---|---|
| `make up` / `make down` | Build and start / stop the stack |
| `make username` | Create the first admin user |
| `make logs` | Tail service logs |
| `make test` | Run the core test suite in containers |
| `sudo ./update.sh` | Pull, rebuild and restart |

## Passive providers

Scans query three free, keyless sources; none of them contacts your targets:

| Provider | Used for |
|---|---|
| crt.sh | Hostnames under owned roots; other domains sharing your certificates become review candidates |
| Shodan InternetDB | Open ports, CPEs, vulnerability IDs and tags per IP; hostnames on owned IPs become candidates |
| RIPEstat | ASN, prefix and holder per IP |

Shodan InternetDB is free for non-commercial use; check Shodan's terms before commercial deployment.

## Security

Report vulnerabilities privately; see [.github/SECURITY.md](.github/SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
