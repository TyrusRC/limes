from django.contrib.postgres.fields import ArrayField
from django.db import models
from django.db.models import F, Func, Value
from django.db.models.functions import Cast

from scanEngine.models import Notification


def append_celery_id(model, pk, celery_id):
    model.objects.filter(pk=pk).update(celery_ids=Func(
        F('celery_ids'),
        Cast(Value(celery_id), models.CharField(max_length=100)),
        function='array_append',
        output_field=ArrayField(models.CharField(max_length=100)),
    ))


def notifications_enabled():
    return Notification.objects.filter(send_scan_status_notif=True).exists()
