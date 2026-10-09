import logging
import os
import shutil

from django.conf import settings

logger = logging.getLogger(__name__)

DEFAULT_ROOTS = ('/usr/src/scan_results',)


def _roots(roots):
    roots = roots or (*DEFAULT_ROOTS, settings.LIMES_RESULTS)
    return [os.path.realpath(r) for r in roots]


def safe_rmtree(path, roots=None):
    real = os.path.realpath(path)
    for root in _roots(roots):
        if real != root and real.startswith(root + os.sep):
            if os.path.islink(path):
                raise ValueError(f'refusing to delete symlink {path}')
            shutil.rmtree(real, ignore_errors=True)
            return
    raise ValueError(f'refusing to delete {path}: not inside an allowed root')


def clear_dir(root, roots=None):
    for entry in os.listdir(root):
        target = os.path.join(root, entry)
        if os.path.isdir(target) and not os.path.islink(target):
            safe_rmtree(target, roots=roots or [root])
        else:
            os.remove(target)


def remove_results_dir(path, roots=None):
    """Best-effort delete of a scan's results dir: blank or disallowed paths are skipped, never raised."""
    if not path:
        return
    try:
        safe_rmtree(path, roots=roots)
    except ValueError as e:
        logger.warning(str(e))
