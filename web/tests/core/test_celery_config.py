import os
import tempfile

from django.conf import settings
from django.test import SimpleTestCase

from limes import celery_routing
from limes.celery import app


def registered_tasks():
    import limes.reaper  # noqa: F401
    import limes.tasks  # noqa: F401
    return {name for name in app.tasks if not name.startswith('celery.')}


class CeleryConfigTest(SimpleTestCase):
    def test_every_task_is_planned(self):
        self.assertEqual(registered_tasks() - set(celery_routing.TASK_PLAN), set())

    def test_no_task_pins_its_own_queue(self):
        pinned = [n for n in registered_tasks() if getattr(app.tasks[n], 'queue', None)]
        self.assertEqual(pinned, [])

    def test_only_three_queues(self):
        queues = {q for q, _ in celery_routing.TASK_PLAN.values()}
        self.assertEqual(queues, {'scan', 'io', 'orchestrate'})

    def test_limits(self):
        for name, ann in celery_routing.task_annotations().items():
            self.assertLess(ann['soft_time_limit'], ann['time_limit'], name)
        self.assertGreater(settings.CELERY_BROKER_TRANSPORT_OPTIONS['visibility_timeout'],
                           celery_routing.MAX_TIME_LIMIT)

    def test_recovery_flags(self):
        self.assertTrue(app.conf.task_acks_late)
        self.assertTrue(app.conf.task_reject_on_worker_lost)
        self.assertEqual(app.conf.worker_prefetch_multiplier, 1)


class RedeliveryTest(SimpleTestCase):
    def test_write_results_tolerates_existing_file(self):
        from limes.celery_custom_task import LimesTask
        task = LimesTask()
        path = tempfile.mktemp()
        with open(path, 'w') as f:
            f.write('old')
        task.result, task.output_path, task.task_name = ['new'], path, 't'
        task.write_results()
        with open(path) as f:
            self.assertIn('new', f.read())

    def test_write_results_accepts_int_result(self):
        # vulnerability_scan/code_audit return a count; write() used to raise TypeError
        from limes.celery_custom_task import LimesTask
        task = LimesTask()
        path = tempfile.mktemp()
        task.result, task.output_path, task.task_name = 25, path, 't'
        task.write_results()
        with open(path) as f:
            self.assertEqual(f.read(), '25')
