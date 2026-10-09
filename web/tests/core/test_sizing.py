import os
import tempfile

from django.test import SimpleTestCase

from limes import sizing

GIB = 1024 ** 3
MEMINFO = 'MemTotal:       16384000 kB\nMemFree:  1000 kB\nMemAvailable:    8192000 kB\n'


def make_tree(files):
    root = tempfile.mkdtemp()
    for name, content in files.items():
        with open(os.path.join(root, name), 'w') as f:
            f.write(content)
    return root


class ReadLimitsTest(SimpleTestCase):
    def setUp(self):
        self.meminfo = os.path.join(make_tree({'meminfo': MEMINFO}), 'meminfo')

    def test_cpu_quota(self):
        root = make_tree({'cpu.max': '200000 100000\n'})
        self.assertEqual(sizing.read_cpu_limit(root), 2.0)

    def test_cpu_max_falls_back_to_cpu_count(self):
        root = make_tree({'cpu.max': 'max 100000\n'})
        self.assertEqual(sizing.read_cpu_limit(root), float(os.cpu_count()))

    def test_missing_cgroup_files_fall_back(self):
        root = make_tree({})
        self.assertEqual(sizing.read_cpu_limit(root), float(os.cpu_count()))
        self.assertEqual(sizing.read_mem_limit(root, self.meminfo), 16384000 * 1024)

    def test_memory_limit_capped_by_host_total(self):
        root = make_tree({'memory.max': str(64 * GIB)})
        self.assertEqual(sizing.read_mem_limit(root, self.meminfo), 16384000 * 1024)
        root = make_tree({'memory.max': str(4 * GIB)})
        self.assertEqual(sizing.read_mem_limit(root, self.meminfo), 4 * GIB)

    def test_usage_ratio_excludes_inactive_file_cache(self):
        root = make_tree({'memory.max': str(4 * GIB), 'memory.current': str(3 * GIB),
                          'memory.stat': f'anon 1\ninactive_file {1 * GIB}\n'})
        self.assertAlmostEqual(sizing.memory_usage_ratio(root, self.meminfo), 0.5)

    def test_usage_ratio_without_cgroup_uses_meminfo(self):
        root = make_tree({})
        self.assertAlmostEqual(sizing.memory_usage_ratio(root, self.meminfo), 0.5)


class ComputeTest(SimpleTestCase):
    def test_small_host(self):
        out = sizing.compute(2, 4 * GIB, {})
        self.assertEqual(out, {'SCAN_SLOTS': 2, 'IO_CONCURRENCY': 40, 'WEB_WORKERS': 5})

    def test_memory_bound(self):
        self.assertEqual(sizing.compute(16, 4 * GIB, {})['SCAN_SLOTS'], 2)

    def test_tiny_host_gets_one_slot(self):
        out = sizing.compute(0.5, 1 * GIB, {})
        self.assertEqual(out['SCAN_SLOTS'], 1)
        self.assertEqual(out['WEB_WORKERS'], 2)

    def test_caps(self):
        out = sizing.compute(64, 512 * GIB, {})
        self.assertEqual(out['SCAN_SLOTS'], 32)
        self.assertEqual(out['WEB_WORKERS'], 9)

    def test_env_overrides(self):
        out = sizing.compute(2, 4 * GIB, {'SCAN_SLOTS': '7', 'IO_CONCURRENCY': '', 'DB_POOL_SIZE': '20'})
        self.assertEqual(out['SCAN_SLOTS'], 7)
        self.assertEqual(out['IO_CONCURRENCY'], 20)
