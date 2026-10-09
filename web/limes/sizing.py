"""Size worker pools from the container's real CPU and memory limits (stdlib only)."""
import os
import sys

GIB = 1024 ** 3
PER_SLOT_MEM = int(1.5 * GIB)
RESERVE_MEM = 1 * GIB
CGROUP_ROOT = '/sys/fs/cgroup'
MEMINFO = '/proc/meminfo'


def _read(path):
    with open(path) as f:
        return f.read().strip()


def _meminfo(path):
    values = {}
    with open(path) as f:
        for line in f:
            key, rest = line.split(':', 1)
            values[key] = int(rest.split()[0]) * 1024
    return values


def read_cpu_limit(cgroup_root=CGROUP_ROOT):
    try:
        quota, period = _read(os.path.join(cgroup_root, 'cpu.max')).split()
        if quota != 'max':
            return max(0.1, int(quota) / int(period))
    except (OSError, ValueError):
        pass
    return float(os.cpu_count() or 1)


def read_mem_limit(cgroup_root=CGROUP_ROOT, meminfo=MEMINFO):
    total = _meminfo(meminfo)['MemTotal']
    try:
        raw = _read(os.path.join(cgroup_root, 'memory.max'))
        if raw != 'max':
            return min(int(raw), total)
    except (OSError, ValueError):
        pass
    return total


def memory_usage_ratio(cgroup_root=CGROUP_ROOT, meminfo=MEMINFO):
    try:
        current = int(_read(os.path.join(cgroup_root, 'memory.current')))
        inactive = 0
        for line in _read(os.path.join(cgroup_root, 'memory.stat')).splitlines():
            key, value = line.split()
            if key == 'inactive_file':
                inactive = int(value)
        return max(0, current - inactive) / read_mem_limit(cgroup_root, meminfo)
    except (OSError, ValueError):
        info = _meminfo(meminfo)
        return (info['MemTotal'] - info['MemAvailable']) / info['MemTotal']


def compute(cpus, mem_bytes, env):
    # NOTE: fixed per-slot memory estimate; upgrade path is measured per-tool RSS.
    def pick(name, value):
        return int(env[name]) if env.get(name) else value

    slots_by_mem = max(0, mem_bytes - RESERVE_MEM) // PER_SLOT_MEM
    scan_slots = max(1, min(int(cpus), int(slots_by_mem), 32))
    db_pool = int(env.get('DB_POOL_SIZE') or 40)
    web_workers = max(2, min(9, 2 * int(cpus) + 1))
    return {
        'SCAN_SLOTS': pick('SCAN_SLOTS', scan_slots),
        'IO_CONCURRENCY': pick('IO_CONCURRENCY', min(50, db_pool)),
        'WEB_WORKERS': pick('WEB_WORKERS', web_workers),
    }


def main():
    sizes = compute(read_cpu_limit(), read_mem_limit(), os.environ)
    for key, value in sizes.items():
        sys.stdout.write(f'export {key}={value}\n')


if __name__ == '__main__':
    main()
