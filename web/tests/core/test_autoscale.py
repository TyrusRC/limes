from django.test import SimpleTestCase

from limes.autoscale import decide


class DecideTest(SimpleTestCase):
    def test_grows_to_queue_length_when_healthy(self):
        self.assertEqual(decide(qty=5, procs=2, min_c=1, max_c=8, mem_ratio=0.5, load=1, cpus=8), 3)

    def test_grow_capped_by_max(self):
        self.assertEqual(decide(qty=50, procs=2, min_c=1, max_c=8, mem_ratio=0.5, load=1, cpus=8), 6)

    def test_no_growth_under_memory_pressure(self):
        self.assertEqual(decide(qty=5, procs=2, min_c=1, max_c=8, mem_ratio=0.85, load=1, cpus=8), 0)

    def test_no_growth_when_cpu_saturated(self):
        self.assertEqual(decide(qty=5, procs=2, min_c=1, max_c=8, mem_ratio=0.5, load=8.5, cpus=8), 0)

    def test_shrinks_one_when_memory_critical(self):
        self.assertEqual(decide(qty=5, procs=4, min_c=1, max_c=8, mem_ratio=0.95, load=1, cpus=8), -1)

    def test_never_below_min(self):
        self.assertEqual(decide(qty=0, procs=1, min_c=1, max_c=8, mem_ratio=0.95, load=1, cpus=8), 0)

    def test_shrinks_idle_workers(self):
        self.assertEqual(decide(qty=0, procs=4, min_c=1, max_c=8, mem_ratio=0.5, load=1, cpus=8), -3)
