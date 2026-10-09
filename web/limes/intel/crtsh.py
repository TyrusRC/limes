"""crt.sh certificate transparency search (passive; third-party only)."""
from urllib.parse import quote

import validators


def build_url(root):
    return f'https://crt.sh/?q=%25.{quote(root)}&output=json&exclude=expired'


def _clean(raw):
    n = raw.strip().lower().rstrip('.')
    if n.startswith('*.'):
        n = n[2:]
    return n if n and validators.domain(n) is True else None


def parse(rows):
    certs = []
    if not isinstance(rows, list):
        return certs
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get('id'), int):
            continue
        names = []
        for raw in str(row.get('name_value') or '').split('\n'):
            n = _clean(raw)
            if n and n not in names:
                names.append(n)
        if names:
            certs.append({'id': row['id'], 'names': names})
    return certs
