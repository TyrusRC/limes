"""Report snapshots on disk: LIMES_RESULTS/reports/<project id>/<32 hex>.html, directory 0700, file 0600.
Nothing here is under a static or media URL; the only way out is the authenticated download view, which
re-checks the name and the resolved path (no traversal, no symlink)."""
import os
import re
import uuid

from django.conf import settings

NAME_RE = re.compile(r'[0-9a-f]{32}\.html')


def root(project_id):
    return os.path.join(settings.LIMES_RESULTS, 'reports', str(int(project_id)))


def write(project, html):
    d = root(project.id)
    os.makedirs(d, exist_ok=True)
    for p in (os.path.dirname(d), d):
        os.chmod(p, 0o700)
    name = uuid.uuid4().hex + '.html'
    fd = os.open(os.path.join(d, name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(html.encode('utf-8'))
    return name


def path(run):
    """The file's path, or None when the stored name is not one we wrote."""
    if not NAME_RE.fullmatch(run.file or ''):
        return None
    return os.path.join(root(run.project_id), run.file)


def open_for_download(run):
    p = path(run)
    if p is None or os.path.islink(p):
        return None
    base = os.path.realpath(root(run.project_id))
    if os.path.dirname(os.path.realpath(p)) != base:
        return None
    try:
        return open(p, 'rb')
    except OSError:
        return None


def remove(run_or_name, project_id=None):
    name = getattr(run_or_name, 'file', run_or_name)
    pid = project_id if project_id is not None else run_or_name.project_id
    if NAME_RE.fullmatch(name or ''):
        try:
            os.remove(os.path.join(root(pid), name))
        except OSError:
            pass
