from datetime import timedelta

from django.db.models import F, Max
from django.db.models.functions import Coalesce
from django.utils import timezone

from limes.celery import app
from limes.celery_routing import MAX_TIME_LIMIT
from limes.definitions import FAILED_TASK, INITIATED_TASK, RUNNING_TASK
from limes.tasks import report
from startScan.models import ScanActivity, ScanHistory

STUCK_AFTER = timedelta(seconds=MAX_TIME_LIMIT) + timedelta(minutes=30)
REAPED_MSG = 'Marked failed: no task progress within the time budget'


def find_stuck_scans(now):
    return (ScanHistory.objects
            .filter(scan_status__in=[RUNNING_TASK, INITIATED_TASK])
            .annotate(last_seen=Coalesce(Max('scanactivity__time'), F('start_scan_date')))
            .filter(last_seen__lt=now - STUCK_AFTER))


@app.task(name='reap_stuck_scans', bind=False)
def reap_stuck_scans():
    now = timezone.now()
    reaped = []
    for scan in find_stuck_scans(now):
        ScanActivity.objects.filter(scan_of=scan, status=RUNNING_TASK).update(
            status=FAILED_TASK, error_message=REAPED_MSG, time=now)
        ScanHistory.objects.filter(pk=scan.pk).update(error_message=REAPED_MSG)
        report.delay(ctx={'scan_history_id': scan.pk, 'engine_id': scan.scan_type_id})
        reaped.append(scan.pk)
    return reaped
