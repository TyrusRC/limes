"""DNS resolution of a root's inventory with dnsx (runs inside discovery, before any probe)."""
import logging
import os

from limes import commands
from limes.pipeline import dnsx
from limes.tasks import inventory
from startScan.models import Asset

logger = logging.getLogger(__name__)
DNSX_TIMEOUT = 30 * 60


def resolve_root(project, root_asset, results_dir, run=commands.run):
    """Resolve the root and its hostname assets; returns how many hosts were recorded.
    Best-effort: failures are logged and leave previous resolutions untouched."""
    if not project or not root_asset:
        return 0
    try:
        # NOTE: holds one root's hostnames in memory (tens of thousands is fine).
        assets = {root_asset.value: root_asset}
        for a in Asset.objects.filter(project=project, kind='hostname', parent=root_asset).iterator(chunk_size=2000):
            assets[a.value] = a
        hosts_file = os.path.join(results_dir, 'resolve_hosts.txt')
        out_file = os.path.join(results_dir, 'dnsx.jsonl')
        if os.path.exists(out_file):
            os.remove(out_file)  # never re-read a previous run's answers
        with open(hosts_file, 'w') as f:
            f.write('\n'.join(assets) + '\n')
        res = run(dnsx.build_argv(hosts_file, out_file), timeout=DNSX_TIMEOUT)
        if res is None or res.return_code != 0:
            logger.warning(f'dnsx exited with {getattr(res, "return_code", None)}')
        if not os.path.isfile(out_file):
            return 0
        with open(out_file) as f:
            records = dnsx.parse(f)
        count = 0
        for name, record in records.items():
            asset = assets.get(name)
            if asset is not None:
                inventory.record_resolution(asset, record)
                count += 1
        return count
    except Exception:
        logger.exception('Resolution failed')
        return 0
