"""Crawl stage helpers: katana+gau argv, host filtering, code-artifact collection.

Artifact mechanism: download-based. Code artifacts (.js, .map, exposed .git
files) are fetched with curl from the crawled URL list, so the saved-path -> URL
mapping is built directly and deterministically (no dependence on katana's
stored-response layout).
"""
import hashlib
import logging
import os
import re
from urllib.parse import urlparse

from limes import commands

logger = logging.getLogger(__name__)

MAX_ARTIFACTS = 300
FETCH_TIMEOUT = 60
MAX_FILESIZE = str(10 * 1024 * 1024)
GIT_FILES = ('HEAD', 'config', 'packed-refs', 'logs/HEAD', 'index')
CODE_EXTS = ('.js', '.mjs', '.map')


def build_katana_argv(input_path, depth, header_argv, threads=0, proxy=None):
    """Exact-host scope (-fs fqdn, not rdn); identity headers via header_argv."""
    argv = ['katana', '-list', input_path, '-silent', '-jc', '-kf', 'all',
            '-d', str(depth), '-fs', 'fqdn']
    if proxy:
        argv += ['-proxy', proxy]
    if threads > 0:
        argv += ['-c', str(threads)]
    return argv + list(header_argv)


def build_gau_argv(host, threads=0, proxy=None):
    """gau queries archives, not the target, so it carries no identity."""
    argv = ['gau', host]
    if proxy:
        argv += ['--proxy', proxy]
    if threads > 0:
        argv += ['--threads', str(threads)]
    return argv


def filter_host_urls(lines, host):
    """Keep URLs on `host` or its subdomains (same rule the old grep applied)."""
    rx = re.compile(r'^https?://([a-z0-9-]+[.])*' + re.escape(host) + r'([:/?#].*)?$', re.I)
    return [l.strip() for l in lines if rx.match(l.strip())]


def artifact_source_url(artifact_path, mapping, default=''):
    # Keyed by basename: mantis paths may be absolute, relative or bare.
    return mapping.get(os.path.basename(artifact_path), default)


def _is_code_url(url):
    return urlparse(url).path.lower().endswith(CODE_EXTS)


def _download(url, dest, header_argv, secrets):
    argv = ['curl', '-sS', '-L', '--max-time', '30', '--max-filesize', MAX_FILESIZE,
            '-f', '-o', dest, *header_argv, url]
    try:
        res = commands.run(argv, timeout=FETCH_TIMEOUT, secrets=secrets)
    except Exception as e:  # defensive: a failed fetch must not crash the scan
        logger.warning(f'artifact download failed for {url}: {e}')
        return False
    ok = res.return_code == 0 and os.path.isfile(dest)
    if not ok and os.path.isfile(dest):
        os.unlink(dest)
    return ok


def _dest(art_dir, url):
    ext = os.path.splitext(urlparse(url).path)[1][:8] or '.txt'
    return os.path.join(art_dir, hashlib.sha1(url.encode()).hexdigest()[:16] + ext)


def collect_code_artifacts(results_dir, urls, header_argv=(), secrets=()):
    """Download .js/.map (plus guessed <js>.map) and exposed .git files.

    Returns (artifacts_dir, {saved_basename: source_url}). Never raises on
    network/tool failure; returns what it got.
    """
    art_dir = os.path.join(results_dir, 'code_artifacts')
    os.makedirs(art_dir, exist_ok=True)
    mapping = {}

    code_urls = []
    for u in urls:
        u = u.strip()
        if _is_code_url(u) and u not in code_urls:
            code_urls.append(u)
            if not u.lower().endswith('.map'):
                m = u.split('?')[0] + '.map'
                if m not in code_urls and m not in urls:
                    code_urls.append(m)
    for u in code_urls[:MAX_ARTIFACTS]:
        dest = _dest(art_dir, u)
        if _download(u, dest, header_argv, secrets):
            mapping[os.path.basename(dest)] = u

    origins = []
    for u in urls:
        p = urlparse(u.strip())
        o = f'{p.scheme}://{p.netloc}'
        if p.scheme in ('http', 'https') and p.netloc and o not in origins:
            origins.append(o)
    for o in origins:
        head_url = f'{o}/.git/HEAD'
        head_dest = os.path.join(art_dir, hashlib.sha1(head_url.encode()).hexdigest()[:16] + '.git-HEAD')
        if not _download(head_url, head_dest, header_argv, secrets):
            continue
        with open(head_dest, errors='replace') as f:
            if not f.read(64).startswith('ref:'):  # not a real exposed repo (soft-404)
                os.unlink(head_dest)
                continue
        mapping[os.path.basename(head_dest)] = head_url
        for name in GIT_FILES[1:]:
            gu = f'{o}/.git/{name}'
            gd = os.path.join(art_dir, hashlib.sha1(gu.encode()).hexdigest()[:16] + '.git-' + name.replace('/', '_'))
            if _download(gu, gd, header_argv, secrets):
                mapping[os.path.basename(gd)] = gu
    return art_dir, mapping
