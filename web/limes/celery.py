import os

if os.environ.get('CELERY_POOL') == 'gevent':
    from psycogreen.gevent import patch_psycopg
    patch_psycopg()

import django
from celery import Celery
from celery.signals import setup_logging

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'limes.settings')
django.setup()

# Celery app
app = Celery('limes')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()


@setup_logging.connect()
def config_loggers(*args, **kwargs):
    from logging.config import dictConfig
    dictConfig(app.conf['LOGGING'])
