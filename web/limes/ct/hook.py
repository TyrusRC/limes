#!/usr/bin/python3 -I
"""certspotter hook: copies one discovered certificate into the spool directory, then exits 0.
Stdlib only, run isolated (-I). Everything it reads comes from the public CT log, so it is hostile: the hash is
validated before it becomes a file name, the JSON is opened without following links and size-capped, and the
record is written to a temp file and renamed so the supervisor never sees a partial file. It never exits non-zero
(certspotter would treat that as a failure to record) and prints only a fixed one-line reason to stderr."""
import json
import os
import re
import stat
import sys
import tempfile
import time

MAX_JSON = 256 * 1024
MAX_NAMES = 1000
MAX_NAME_LEN = 253
_HEX64 = re.compile(r'[0-9a-f]{64}')


def _skip(reason):
    sys.stderr.write('ct-hook: skipped (%s)\n' % reason)
    return 0


def _read_json(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_JSON:
            return None
        raw = os.read(fd, MAX_JSON + 1)
    finally:
        os.close(fd)
    if len(raw) > MAX_JSON:
        return None
    return json.loads(raw)


def _publish(spool, final_dir, final_name, record):
    """Atomic write: mkstemp in spool/.tmp, then rename into place."""
    tmp_dir = os.path.join(spool, '.tmp')
    os.makedirs(tmp_dir, mode=0o700, exist_ok=True)
    os.makedirs(final_dir, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=tmp_dir)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(record, f)
        os.replace(tmp, os.path.join(final_dir, final_name))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _s(v, limit):
    return v[:limit] if isinstance(v, str) else ''


def _discovered(env, spool):
    tbs = env.get('TBS_SHA256', '')
    if not _HEX64.fullmatch(tbs):
        return _skip('bad hash')
    try:
        doc = _read_json(env.get('JSON_FILENAME', ''))
    except (OSError, ValueError, RecursionError):
        return _skip('unreadable certificate file')
    if not isinstance(doc, dict):
        return _skip('unusable certificate file')
    names = doc.get('dns_names')
    if not isinstance(names, list):
        return _skip('no names')
    kept = [n for n in names if isinstance(n, str) and len(n) <= MAX_NAME_LEN][:MAX_NAMES]
    idx = env.get('ENTRY_INDEX', doc.get('entry_index'))
    try:
        idx = int(idx)
    except (TypeError, ValueError):
        idx = None
    record = {'v': 1, 'tbs_sha256': tbs,
              'cert_sha256': env.get('CERT_SHA256') or doc.get('cert_sha256'),
              'dns_names': kept, 'names_total': len(names),
              'issuer_dn': _s(env.get('ISSUER_DN') or doc.get('issuer_dn') or doc.get('issuer'), 500),
              'not_before': env.get('NOT_BEFORE_RFC3339') or doc.get('not_before'),
              'not_after': env.get('NOT_AFTER_RFC3339') or doc.get('not_after'),
              'log_uri': _s(env.get('LOG_URI') or doc.get('log_uri'), 500), 'entry_index': idx}
    _publish(spool, spool, tbs + '.json', record)
    return 0


def _health(env, spool):
    event = env['EVENT']
    record = {'event': event, 'summary': _s(env.get('SUMMARY', ''), 2048), 'at': time.time()}
    _publish(spool, os.path.join(spool, '_health'), '%d.json' % time.time_ns(), record)
    return 0


def main(env, spool):
    try:
        event = env.get('EVENT')
        if event == 'discovered_cert':
            return _discovered(env, spool)
        if event in ('error', 'malformed_cert'):
            return _health(env, spool)
    except Exception:
        sys.stderr.write('ct-hook: failed\n')
    return 0


if __name__ == '__main__':
    sys.exit(main(os.environ, os.environ.get('LIMES_CT_SPOOL', '/var/lib/ct-watch/spool')))
