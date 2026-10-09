"""Create .env from .env.example with fresh secrets and memory limits sized to this host."""
import argparse
import base64
import os
import secrets
import sys

SECRET_KEYS = ('AUTHORITY_PASSWORD', 'POSTGRES_PASSWORD', 'DJANGO_SUPERUSER_PASSWORD', 'LIMES_SECRET_KEY')


def host_mem_gib():
    with open('/proc/meminfo') as f:
        for line in f:
            if line.startswith('MemTotal:'):
                return int(line.split()[1]) // (1024 * 1024)
    return 8


def sized(mem_gib):
    usable = max(4, mem_gib - 2)
    scan = max(2, int(usable * 0.6))
    io = max(1, int(usable * 0.15))
    web = max(1, int(usable * 0.1))
    return {'WORKER_SCAN_MEM': f'{scan}g', 'WORKER_IO_MEM': f'{io}g', 'WEB_MEM': f'{web}g',
            'WORKER_ORCH_MEM': '1g', 'REDIS_MAXMEMORY': f'{max(256, int(usable * 1024 * 0.05))}mb'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', default='.env')
    parser.add_argument('--example', default='.env.example')
    args = parser.parse_args()
    if os.path.exists(args.out):
        sys.exit(f'{args.out} already exists; refusing to overwrite')
    values = {key: secrets.token_urlsafe(32) for key in SECRET_KEYS}
    values['LIMES_SECRET_KEY_ENCRYPTION'] = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    values.update(sized(host_mem_gib()))
    lines = []
    with open(args.example) as f:
        for line in f:
            key = line.split('=', 1)[0]
            if '=' in line and not line.startswith('#') and key in values:
                line = f'{key}={values[key]}\n'
            lines.append(line)
    fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.writelines(lines)
    print(f'wrote {args.out}')


if __name__ == '__main__':
    main()
