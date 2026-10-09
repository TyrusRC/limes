#!/bin/bash
set -euo pipefail
exec celery -A limes.celery beat -l info --scheduler django_celery_beat.schedulers:DatabaseScheduler
