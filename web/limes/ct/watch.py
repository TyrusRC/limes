"""Certificate watcher: supervises a self-hosted certspotter child and drains its spool into limes.ct.ingest.
The child's hook (limes.ct.hook) writes only matches to the spool; this process is the one place that touches the DB.
Spool files and certificate contents are hostile: names are matched by regex, links are never followed and the child
gets a minimal environment, never the app's secrets. The child is started from an argv list, never a shell."""
import hashlib
import json
import logging
import math
import os
import re
import signal
import subprocess
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone as dt_tz

from django.conf import settings
from django.db import close_old_connections
from django.utils import timezone
from django_redis import get_redis_connection

from dashboard.models import Project
from dashboard.stats import invalidate
from limes.alerts.deliver import deliver_immediate
from limes.ct import ingest

logger = logging.getLogger(__name__)

HEARTBEAT = 'limes:ct:watch'
HEARTBEAT_TTL = 600
LOOP_SECONDS = 5
HEALTH_KEEP = 100
SPOOL_FAIL_LIMIT = 3
HOOK_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'hook.py')
WATCHLIST_EVERY = 60
STOP_WAIT = 30
TMP_MAX_AGE = 3600
HEALTH_MAX_BYTES = 8192
_SPOOL_FILE = re.compile(r'[0-9a-f]{64}\.json')
_HEALTH_FILE = re.compile(r'[0-9]{1,20}\.json')
_WATCH_NAME = re.compile(r'[a-z0-9.-]+')
_FAILS = {}  # file hash -> failed ingests in this process


def paths(state_dir=None):
    state = state_dir or settings.CT_STATE_DIR
    return {'state': state, 'spool': os.path.join(state, 'spool'), 'tmp': os.path.join(state, 'spool', '.tmp'),
            'health': os.path.join(state, 'spool', '_health'), 'watchlist': os.path.join(state, 'watchlist.txt')}


def watchlist(max_entries=None):
    """(lines, dropped, sha256 hex) for certspotter's -watchlist file. A leading dot means the name and everything
    below it. # NOTE: capped at LIMES_CT_WATCHLIST_MAX; owned names win and lookalikes are dropped first. Upgrade
    path: a measured cap once certspotter's per-entry cost is known."""
    cap = settings.CT_WATCHLIST_MAX if max_entries is None else max_entries
    idx = ingest.load_index()

    def ok(names):
        return sorted({n for n in names if _WATCH_NAME.fullmatch(n)})
    roots = ['.' + n for n in ok(idx.roots)]
    hosts = ok(idx.hosts)
    look = ['.' + n for n in ok(idx.lookalikes)]
    total = len(roots) + len(hosts) + len(look)
    if len(roots) + len(hosts) + len(look) > cap:
        look = look[:max(0, cap - len(roots) - len(hosts))]
    if len(roots) + len(hosts) > cap:
        hosts = hosts[:max(0, cap - len(roots))]
    lines = roots + hosts + look
    return lines, total - len(lines), hashlib.sha256('\n'.join(lines).encode()).hexdigest()


def command(p, watchlist_file):
    return ['certspotter', '-watchlist', watchlist_file, '-state_dir', p['state'], '-script', HOOK_PATH,
            '-no_save', '-start_at_end', '-healthcheck', '1h']


def _iso(t):
    return datetime.fromtimestamp(t, dt_tz.utc).isoformat()


def _open_nofollow(path, limit):
    """The bytes of a regular file read without following a link, or None when it is not one or exceeds limit."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if (st.st_mode & 0o170000) != 0o100000 or st.st_size > limit:
            return None
        raw = os.read(fd, limit + 1)
    finally:
        os.close(fd)
    return raw if len(raw) <= limit else None


def _unlink(path):
    try:
        os.unlink(path)
    except OSError:
        pass


def _sweep_tmp(tmp_dir, now_ts):
    try:
        with os.scandir(tmp_dir) as it:
            for e in list(it):
                try:
                    if now_ts - e.stat(follow_symlinks=False).st_mtime > TMP_MAX_AGE and not e.is_dir(follow_symlinks=False):
                        _unlink(e.path)
                except OSError:
                    pass
    except OSError:
        pass


def drain_spool(spool, limit, now, index_loader=ingest.load_index):
    """Ingest up to `limit` spooled certificates, oldest first. Returns ingested/invalid/failed/depth/projects.
    NOTE: the backlog waits on disk, bounded by the volume; only matches are written, so it stays small. Upgrade
    path: a size alarm feeding the degraded state (Task 5's spool rule)."""
    out = {'ingested': 0, 'invalid': 0, 'failed': 0, 'depth': 0, 'projects': set()}
    try:
        with os.scandir(spool) as it:
            entries = list(it)
    except OSError:
        return out
    _sweep_tmp(os.path.join(spool, '.tmp'), time.time())
    cands = []
    for e in entries:
        try:
            if e.is_dir(follow_symlinks=False):
                continue  # .tmp, _health, anything else we did not create: left alone
            st = e.stat(follow_symlinks=False)
            if e.is_file(follow_symlinks=False) and _SPOOL_FILE.fullmatch(e.name) and st.st_size <= ingest.SPOOL_MAX_BYTES:
                cands.append((st.st_mtime, e.name, e.path))
                continue
        except OSError:
            continue
        _unlink(e.path)  # a link (never followed), a stray name or an oversize file
        out['invalid'] += 1
    cands.sort()
    out['depth'] = len(cands)
    batch = cands[:limit]
    if not batch:
        return out
    try:
        index = index_loader()
    except Exception as e:
        logger.warning('ct spool: could not load the match index (%s)', type(e).__name__)
        out['failed'] = len(batch)
        return out
    for mtime, name, path in batch:
        key = name[:-5]
        try:
            raw = _open_nofollow(path, ingest.SPOOL_MAX_BYTES)
        except OSError:
            raw = None
        record = ingest.parse_record(raw) if raw is not None else None
        if record is None:
            _unlink(path)
            out['invalid'] += 1
            out['depth'] -= 1
            continue
        try:
            touched = ingest.ingest(record, 'certspotter', index, now, seen_at=mtime)
        except Exception as e:
            _FAILS[key] = _FAILS.get(key, 0) + 1
            out['failed'] += 1
            if _FAILS[key] >= SPOOL_FAIL_LIMIT:
                logger.error('ct spool: giving up on %s after %s failures (%s)', key[:16], _FAILS.pop(key), type(e).__name__)
                _unlink(path)
                out['depth'] -= 1
            else:
                logger.warning('ct spool: ingest of %s failed (%s)', key[:16], type(e).__name__)
            continue
        _FAILS.pop(key, None)
        _unlink(path)
        out['ingested'] += 1
        out['depth'] -= 1
        out['projects'] |= set(touched)
    for pid in sorted(out['projects']):
        try:
            project = Project.objects.filter(pk=pid).first()
            if project is not None:
                deliver_immediate(project)
            invalidate(pid)
        except Exception as e:
            logger.warning('ct spool: delivery for project %s failed (%s)', pid, type(e).__name__)
    return out


def read_health(health_dir):
    """The newest hook error as {'last_error_at', 'last_error_summary'}; keeps only the newest HEALTH_KEEP files."""
    try:
        with os.scandir(health_dir) as it:
            files = sorted((int(e.name[:-5]), e.path) for e in it
                           if _HEALTH_FILE.fullmatch(e.name) and e.is_file(follow_symlinks=False))
    except OSError:
        return None
    for _, path in files[:-HEALTH_KEEP]:
        _unlink(path)
    for ns, path in reversed(files[-HEALTH_KEEP:]):
        try:
            rec = json.loads(_open_nofollow(path, HEALTH_MAX_BYTES) or b'')
            summary = rec['summary'] if isinstance(rec, dict) and isinstance(rec.get('summary'), str) else ''
        except (OSError, ValueError, KeyError, RecursionError):
            continue
        return {'last_error_at': _iso(ns / 1e9), 'last_error_summary': summary[:2048]}
    return None


class Supervisor:
    def __init__(self, popen=subprocess.Popen, clock=time.monotonic, wall=time.time):
        self.popen, self.clock, self.wall = popen, clock, wall
        self.proc = None
        self.started = None
        self.started_wall = None
        self.running_hash = None
        self.restarts = deque(maxlen=50)
        self.wl = None
        self.wl_at = None
        self.last_ingest = self.last_match = None
        self.last_error = {'last_error_at': None, 'last_error_summary': None}
        self.ever_started = False

    def stop(self):
        proc, self.proc = self.proc, None
        if proc is None or proc.poll() is not None:
            return
        proc.terminate()
        try:
            proc.wait(timeout=STOP_WAIT)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    def _write_watchlist(self, p, lines):
        os.makedirs(p['state'], mode=0o700, exist_ok=True)
        tmp = p['watchlist'] + '.new'
        with open(tmp, 'w') as f:
            f.write('\n'.join(lines) + '\n')
        os.replace(tmp, p['watchlist'])

    def _start(self, p):
        lines, _, h = self.wl
        self._write_watchlist(p, lines)
        for d in (p['spool'], p['tmp'], p['health']):
            os.makedirs(d, mode=0o700, exist_ok=True)
        env = {'PATH': os.environ.get('PATH', '/usr/local/bin:/usr/bin:/bin'), 'HOME': p['state'],
               'LIMES_CT_SPOOL': p['spool']}  # nothing else: no database or Redis secrets reach the child
        self.proc = self.popen(command(p, p['watchlist']), stdin=subprocess.DEVNULL, env=env)
        now = self.clock()
        if self.ever_started:
            self.restarts.append(now)
        self.ever_started = True
        self.started, self.started_wall, self.running_hash = now, self.wall(), h

    def _supervise(self, p):
        now = self.clock()
        if self.wl is None or now - self.wl_at >= WATCHLIST_EVERY:
            self.wl, self.wl_at = watchlist(), now
        if not self.wl[0]:
            self.stop()
            return 'idle'
        if self.proc is not None and self.proc.poll() is not None:
            self.proc = None
        if self.proc is None:
            recent = [t for t in self.restarts if now - t < 600]
            if len(recent) >= 5 and self.started is not None and now - self.started < 60:
                return 'backoff'  # a crash loop waits a minute between starts
            self._start(p)
        elif self.wl[2] != self.running_hash and now - self.started >= settings.CT_WATCH_RESTART_MIN:
            self.stop()
            self._start(p)
        return 'running'

    def step(self, now):
        p = paths()
        if settings.CT_WATCH and settings.CONTINUOUS_SCANS:
            state = self._supervise(p)
        else:
            self.stop()
            state = 'off'
        limit = math.ceil(settings.CT_INGEST_PER_MIN * LOOP_SECONDS / 60)
        res = drain_spool(p['spool'], limit, now)
        if res['ingested']:
            self.last_ingest = now.isoformat()
        if res['projects']:
            self.last_match = now.isoformat()
        err = read_health(p['health'])
        if err:
            self.last_error = err
        close_old_connections()
        wall = self.wall()
        lines, dropped, h = self.wl or ([], 0, None)
        recent_err = self.last_error['last_error_at'] and wall - datetime.fromisoformat(self.last_error['last_error_at']).timestamp() < 600
        hb = {'pid_alive': self.proc is not None and self.proc.poll() is None,
              'started_at': _iso(self.started_wall) if self.started_wall else None,
              'restarts_10m': len([t for t in self.restarts if self.clock() - t < 600]),
              'watchlist_size': len(lines), 'watchlist_dropped': dropped, 'watchlist_hash': h,
              'last_ingest_at': self.last_ingest, 'last_match_at': self.last_match, 'spool_depth': res['depth'],
              'health': 'error' if recent_err else 'ok', **self.last_error, 'state': state, 'at': _iso(wall)}
        try:
            get_redis_connection('default').set(HEARTBEAT, json.dumps(hb), ex=HEARTBEAT_TTL)
        except Exception as e:
            logger.warning('ct watch: heartbeat not written (%s)', type(e).__name__)
        return hb


def run():
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    sup = Supervisor()
    try:
        while not stop.is_set():
            try:
                sup.step(timezone.now())
            except Exception as e:
                logger.error('ct watch: loop failed (%s)', type(e).__name__)
            stop.wait(LOOP_SECONDS)
    finally:
        sup.stop()


def health_exit_code(now=None):
    now = now or timezone.now()
    try:
        raw = get_redis_connection('default').get(HEARTBEAT)
        at = datetime.fromisoformat(json.loads(raw)['at'])
    except Exception:
        return 1
    return 0 if (now - at).total_seconds() <= settings.CT_WATCH_STALE else 1
