"""Celery autoscaler that refuses to grow under memory or CPU pressure."""
import os

from celery.worker.autoscale import Autoscaler

from limes import sizing

GROW_BELOW_MEM = 0.80
SHRINK_ABOVE_MEM = 0.90


def decide(qty, procs, min_c, max_c, mem_ratio, load, cpus):
    if mem_ratio >= SHRINK_ABOVE_MEM and procs > min_c:
        return -1
    target = max(min(qty, max_c), min_c)
    if target > procs:
        if mem_ratio >= GROW_BELOW_MEM or load >= cpus:
            return 0
        return target - procs
    if target < procs:
        return target - procs
    return 0


class MemoryAwareAutoscaler(Autoscaler):
    def _maybe_scale(self, req=None):
        delta = decide(
            qty=self.qty,
            procs=self.processes,
            min_c=self.min_concurrency,
            max_c=self.max_concurrency,
            mem_ratio=sizing.memory_usage_ratio(),
            load=os.getloadavg()[0],
            cpus=sizing.read_cpu_limit(),
        )
        if delta > 0:
            self.scale_up(delta)
            return True
        if delta < 0:
            self.scale_down(-delta)
            return True
        return False
