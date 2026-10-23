import base64
import hashlib
import environ

env = environ.FileAwareEnv()

import mimetypes
import os

from limes.init import first_run
from limes.utilities import LimesTaskFormatter

mimetypes.add_type("text/javascript", ".js", True)
mimetypes.add_type("text/css", ".css", True)

# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#       LIMES CONFIGURATIONS
# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Take environment variables from .env file
environ.Env.read_env(os.path.join(BASE_DIR, os.pardir, '.env'))

# Root env vars
LIMES_HOME = env('LIMES_HOME', default='/usr/src/app')
LIMES_RESULTS = env('LIMES_RESULTS', default=f'{LIMES_HOME}/scan_results')
LIMES_CACHE_ENABLED = env.bool('LIMES_CACHE_ENABLED', default=False)
LIMES_RECORD_ENABLED = env.bool('LIMES_RECORD_ENABLED', default=True)
LIMES_RAISE_ON_ERROR = env.bool('LIMES_RAISE_ON_ERROR', default=False)
# On: auto-confirm still needs a registry-verified delegation (limes.intel.delegation); false only flags
ATTRIBUTION_AUTO_CONFIRM = env.bool('LIMES_ATTRIBUTION_AUTO_CONFIRM', default=True)
# Change-alert webhook: signed JSON POST (HMAC-SHA256 in X-Limes-Signature); empty url or secret disables it
ALERT_WEBHOOK_URL = env('LIMES_ALERT_WEBHOOK_URL', default='')
ALERT_WEBHOOK_SECRET = env('LIMES_ALERT_WEBHOOK_SECRET', default='')
ALERT_WEBHOOK_ALLOW_HTTP = env.bool('LIMES_ALERT_WEBHOOK_ALLOW_HTTP', default=False)
# Rediscover owned roots on their cadence_tier (limes.continuous); false stops all automatic scans
CONTINUOUS_SCANS = env.bool('LIMES_CONTINUOUS_SCANS', default=True)
# MCP server (limes.mcp): off by default; writes need their own switch
MCP_ENABLED = env.bool('LIMES_MCP_ENABLED', default=False)
MCP_WRITES_ENABLED = env.bool('LIMES_MCP_WRITES_ENABLED', default=False)
# Tier of assets an agent adds through MCP add_assets (anything but candidate/owned_host/owned_root counts as candidate).
MCP_ADD_TIER = env.str('LIMES_MCP_ADD_TIER', default='candidate')
MCP_ALLOWED_ORIGINS = env.list('LIMES_MCP_ALLOWED_ORIGINS', default=[])
MCP_ALLOWED_HOSTS = env.list('LIMES_MCP_ALLOWED_HOSTS', default=[])
MCP_RATE_PER_MIN = max(1, env.int('LIMES_MCP_RATE_PER_MIN', default=60))
MCP_WRITE_RATE_PER_MIN = max(1, env.int('LIMES_MCP_WRITE_RATE_PER_MIN', default=10))
# Certificate watch (limes.ct.watch): opt-in self-hosted certspotter, `make up REALTIME=1` with LIMES_CT_WATCH=true
CT_WATCH = env.bool('LIMES_CT_WATCH', default=False)
CT_WATCH_RESTART_MIN = env.int('LIMES_CT_WATCH_RESTART_MIN', default=300)  # seconds between watchlist-driven restarts
CT_WATCHLIST_MAX = env.int('LIMES_CT_WATCHLIST_MAX', default=5000)
CT_INGEST_PER_MIN = env.int('LIMES_CT_INGEST_PER_MIN', default=600)  # spool files ingested per minute
CT_STATE_DIR = env('LIMES_CT_STATE_DIR', default='/var/lib/ct-watch')
# Cert Spotter API fallback (limes.ct.api): opt-in, key from the environment only. The free tier allows 10 requests/hour.
CERTSPOTTER_API_KEY = env('LIMES_CERTSPOTTER_API_KEY', default='').strip()
CERTSPOTTER_HOURLY_BUDGET = max(1, min(env.int('LIMES_CERTSPOTTER_HOURLY_BUDGET', default=7), 10))
CT_DEGRADED_GRACE_MIN = env.int('LIMES_CT_DEGRADED_GRACE_MIN', default=15)  # minutes a never-alerted degraded watch waits before alerting
CT_WATCH_STALE = env.int('LIMES_CT_WATCH_STALE', default=180)  # seconds before a silent watcher fails its healthcheck
# Event-driven checks (limes.event_queue): capped queue, per-asset cooldown (s), per-project hourly burst, and the
# share of each monitor tick's budget the queue may take
EVENT_CHECKS = env.bool('LIMES_EVENT_CHECKS', default=True)
LIVE_POLL_SECONDS = max(0, env.int('LIMES_LIVE_POLL_SECONDS', default=30))  # Overview refresh; 0 turns polling off
EVENT_QUEUE_MAX = max(1, env.int('LIMES_EVENT_QUEUE_MAX', default=1000))
EVENT_COOLDOWN = env.int('LIMES_EVENT_COOLDOWN', default=900)
EVENT_BURST = max(1, env.int('LIMES_EVENT_BURST', default=200))
CT_EVENT_WINDOW = env.int('LIMES_CT_EVENT_WINDOW', default=3600)  # seconds one cert_new digest row coalesces over
CT_NEW_HOSTS_PER_HOUR = env.int('LIMES_CT_NEW_HOSTS_PER_HOUR', default=200)  # owned hostnames certificates may add per project per hour
# crown-jewel names re-resolved (DNS only) at most this often (s; 0 = off), at most DNS_WATCH_PER_TICK a tick
DNS_WATCH_INTERVAL = env.int('LIMES_DNS_WATCH_INTERVAL', default=900)
DNS_WATCH_PER_TICK = max(1, env.int('LIMES_DNS_WATCH_PER_TICK', default=30))
EVENT_SHARE = min(0.9, max(0.1, env.float('LIMES_EVENT_SHARE', default=0.5)))
# Expand owned ranges and ASNs into per-IP child assets (PTR + InternetDB lookups). Off by default.
# InternetDB is free for non-commercial use only; commercial use needs a Shodan enterprise license.
# NOTE: its terms are only partly published and 1 req/s is Limes's own throttle. Upgrade path: a paid key or Limes's own scanner.
RANGE_ENUMERATION = env.bool('LIMES_RANGE_ENUMERATION', default=False)
# NOTE: per-project owned address cap, clamped to 1..65536 (0 or negative would silently refuse every range); raising it raises lookup volume.
RANGE_ADDRESS_CAP = max(1, min(env.int('LIMES_RANGE_ADDRESS_CAP', default=4096), 65536))
INTERNETDB_DAILY_BUDGET = env.int('LIMES_INTERNETDB_DAILY_BUDGET', default=5000)
PTR_DAILY_BUDGET = env.int('LIMES_PTR_DAILY_BUDGET', default=10000)
# Third-party reputation feeds (limes/feeds). Opt-in names: blocklist_de, cins (terms unclear, off by default).
FEEDS_OPTIN = env.list('LIMES_FEEDS_OPTIN', default=[])
# Sent only to abuse.ch hosts, never logged. Empty: Feodo is fetched without a key.
ABUSECH_AUTH_KEY = env('LIMES_ABUSECH_AUTH_KEY', default='')
# Spamhaus DQS key (optional ZEN lookups per owned IP); part of every query name, so never logged. Empty: no lookups.
SPAMHAUS_DQS_KEY = env('LIMES_SPAMHAUS_DQS_KEY', default='')
# Have I Been Pwned key (optional domain-breach counts for owned roots); sent only in a header, never logged. Empty: off.
HIBP_API_KEY = env('LIMES_HIBP_API_KEY', default='')
# Lookalike domains of owned roots (limes/lookalike): DNS, RDAP and crt.sh only. LOOKALIKE_HTTP adds one GET per
# registered lookalike per week, which tells its operator someone is looking; off by default.
LOOKALIKE_ENABLED = env.bool('LIMES_LOOKALIKE_ENABLED', default=True)
LOOKALIKE_DNS_DAILY_BUDGET = env.int('LIMES_LOOKALIKE_DNS_DAILY_BUDGET', default=5000)
RDAP_DAILY_BUDGET = env.int('LIMES_RDAP_DAILY_BUDGET', default=500)
LOOKALIKE_HTTP = env.bool('LIMES_LOOKALIKE_HTTP', default=False)

# Common env vars
DEBUG = env.bool('DEBUG', default=False)
DOMAIN_NAME = env('DOMAIN_NAME', default='localhost:8000')
TEMPLATE_DEBUG = env.bool('TEMPLATE_DEBUG', default=False)
SECRET_FILE = os.path.join(LIMES_HOME, 'secret')
DEFAULT_ENABLE_HTTP_CRAWL = env.bool('DEFAULT_ENABLE_HTTP_CRAWL', default=True)
DEFAULT_RATE_LIMIT = env.int('DEFAULT_RATE_LIMIT', default=150) # requests / second
DEFAULT_HTTP_TIMEOUT = env.int('DEFAULT_HTTP_TIMEOUT', default=5) # seconds
DEFAULT_RETRIES = env.int('DEFAULT_RETRIES', default=1)
DEFAULT_THREADS = env.int('DEFAULT_THREADS', default=30)
DEFAULT_GET_GPT_REPORT = env.bool('DEFAULT_GET_GPT_REPORT', default=True)

# Globals
ALLOWED_HOSTS = ['*']
SECRET_KEY = first_run(SECRET_FILE, BASE_DIR)

# Fernet key for secret scan-identity headers at rest. Production MUST set
# LIMES_SECRET_KEY_ENCRYPTION (a Fernet key); the SECRET_KEY-derived fallback
# only keeps dev/tests working and ties ciphertext to SECRET_KEY.
HEADER_ENCRYPTION_KEY = env('LIMES_SECRET_KEY_ENCRYPTION', default=None) or base64.urlsafe_b64encode(
    hashlib.sha256(SECRET_KEY.encode()).digest()).decode()

# Limes version
# reads current version from a file called .version
VERSION_FILE = os.path.join(BASE_DIR, '.version')
if os.path.exists(VERSION_FILE):
    with open(VERSION_FILE, 'r') as f:
        _version = f.read().strip()
else:
    _version = 'unknown'

# removes v from _version if exists
if _version.startswith('v'):
    _version = _version[1:]

LIMES_CURRENT_VERSION = _version

# Databases
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': env('POSTGRES_DB'),
        'USER': env('POSTGRES_USER'),
        'PASSWORD': env('POSTGRES_PASSWORD'),
        'HOST': env('POSTGRES_HOST'),
        'PORT': env('POSTGRES_PORT'),
        'CONN_MAX_AGE': 0,
        'DISABLE_SERVER_SIDE_CURSORS': True,
        # 'OPTIONS':{
        #     'sslmode':'verify-full',
        #     'sslrootcert': os.path.join(BASE_DIR, 'ca-certificate.crt')
        # }
    }
}

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.humanize',
    'rest_framework',
    'rest_framework_datatables',
    'dashboard.apps.DashboardConfig',
    'targetApp.apps.TargetappConfig',
    'scanEngine.apps.ScanengineConfig',
    'startScan.apps.StartscanConfig',
    'django_ace',
    'django_celery_beat',
    'mathfilters',
    'drf_yasg',
    'rolepermissions'
]
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'login_required.middleware.LoginRequiredMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [(os.path.join(BASE_DIR, 'templates'))],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'limes.context_processors.projects',
                'limes.context_processors.version_context',
            ],
    },
}]
ROOT_URLCONF = 'limes.urls'
REST_FRAMEWORK = {
    'DEFAULT_RENDERER_CLASSES': (
        'rest_framework.renderers.JSONRenderer',
        'rest_framework.renderers.BrowsableAPIRenderer',
        'rest_framework_datatables.renderers.DatatablesRenderer',
    ),
    'DEFAULT_FILTER_BACKENDS': (
        'rest_framework_datatables.filters.DatatablesFilterBackend',
    ),
    'DEFAULT_PAGINATION_CLASS':(
        'rest_framework_datatables.pagination.DatatablesPageNumberPagination'
    ),
    'PAGE_SIZE': 500,
}
WSGI_APPLICATION = 'limes.wsgi.application'

# Password validation
# https://docs.djangoproject.com/en/2.2/ref/settings/#auth-password-validators
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.' +
                'UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.' +
                'MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.' +
                'CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.' +
                'NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/2.2/topics/i18n/
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_L10N = True
USE_TZ = True

MEDIA_URL = '/media/'
MEDIA_ROOT = '/usr/src/scan_results/'
FILE_UPLOAD_MAX_MEMORY_SIZE = 100000000
FILE_UPLOAD_PERMISSIONS = 0o644
STATIC_URL = '/staticfiles/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, "static"),
]

LOGIN_REQUIRED_IGNORE_VIEW_NAMES = [
    'login',
    'healthz',
]

LOGIN_URL = 'login'
LOGIN_REDIRECT_URL = 'onboarding'
LOGOUT_REDIRECT_URL = 'login'

# Tool Location
TOOL_LOCATION = '/usr/src/app/tools/'

# Number of endpoints that have the same content_length
DELETE_DUPLICATES_THRESHOLD = 10

'''
CELERY settings
'''
from limes import celery_routing

CELERY_BROKER_URL = env("CELERY_BROKER", default="redis://redis:6379/0")
CELERY_RESULT_BACKEND = env("CELERY_BROKER", default="redis://redis:6379/0")
CELERY_ENABLE_UTC = False
CELERY_TIMEZONE = 'UTC'
CELERY_IGNORE_RESULTS = False
CELERY_EAGER_PROPAGATES_EXCEPTIONS = True
CELERY_TRACK_STARTED = True
CELERY_BROKER_CONNECTION_RETRY_ON_STARTUP = True
CELERY_IMPORTS = ('limes.tasks', 'limes.reaper', 'limes.continuous', 'limes.scoring',
                  'limes.alerts.digest', 'limes.alerts.waiver_tasks', 'limes.owned_ranges', 'limes.monitor',
                  'limes.mcp.audit', 'limes.feeds.tasks', 'limes.hibp', 'limes.lookalike.tasks', 'limes.ct.api')
CELERY_BEAT_SCHEDULE = {
    'reap-stuck-scans': {'task': 'reap_stuck_scans', 'schedule': 300.0},
    # expires: a tick queued while workers were down is dropped, not run late alongside the next
    'dispatch-due-scans': {'task': 'dispatch_due_scans', 'schedule': 60.0, 'options': {'expires': 55}},
    'enumerate-ranges': {'task': 'enumerate_ranges', 'schedule': 60.0, 'options': {'expires': 55}},
    'monitor-assets': {'task': 'monitor_assets', 'schedule': 60.0, 'options': {'expires': 55}},
    'refresh-feeds': {'task': 'refresh_feeds', 'schedule': 3600.0, 'options': {'expires': 3300}},
    'hibp-sync': {'task': 'hibp_sync', 'schedule': 86400.0},
    'generate-lookalikes': {'task': 'generate_lookalikes', 'schedule': 86400.0},
    'lookalike-tick': {'task': 'lookalike_tick', 'schedule': 60.0, 'options': {'expires': 55}},
    'drain-events': {'task': 'monitor_assets', 'schedule': 15.0, 'kwargs': {'events_only': True},
                     'options': {'expires': 14}},
    'poll-ct-api': {'task': 'poll_ct_api', 'schedule': 60.0, 'options': {'expires': 55}},
    'age-assets': {'task': 'age_assets', 'schedule': 3600.0},
    'snapshot-scores': {'task': 'snapshot_scores', 'schedule': 86400.0},
    'send-digest': {'task': 'send_digest', 'schedule': 86400.0},
    'expire-waivers': {'task': 'expire_waivers', 'schedule': 86400.0},
    'purge-mcp-logs': {'task': 'purge_mcp_logs', 'schedule': 86400.0},
}
CELERY_TASK_ROUTES = celery_routing.task_routes()
CELERY_TASK_ANNOTATIONS = celery_routing.task_annotations()
CELERY_TASK_DEFAULT_QUEUE = celery_routing.IO
CELERY_TASK_ACKS_LATE = True
CELERY_TASK_REJECT_ON_WORKER_LOST = True
CELERY_WORKER_PREFETCH_MULTIPLIER = 1
CELERY_WORKER_AUTOSCALER = 'limes.autoscale:MemoryAwareAutoscaler'
CELERY_BROKER_TRANSPORT_OPTIONS = {'visibility_timeout': celery_routing.MAX_TIME_LIMIT + celery_routing.HOUR}
CELERY_RESULT_BACKEND_TRANSPORT_OPTIONS = CELERY_BROKER_TRANSPORT_OPTIONS
CELERY_RESULT_EXPIRES = 24 * celery_routing.HOUR
'''
ROLES and PERMISSIONS
'''
ROLEPERMISSIONS_MODULE = 'limes.roles'
ROLEPERMISSIONS_REDIRECT_TO_LOGIN = True

'''
Cache settings
'''
LIMES_TASK_IGNORE_CACHE_KWARGS = ['ctx']


DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

'''
LOGGING settings
'''
# Log files go in the working directory unless LIMES_LOG_DIR is set (the read-only ct-watch container sets /tmp).
LOG_DIR = env('LIMES_LOG_DIR', default='')
LOGGING = {
    'version': 1,
    'disable_existing_loggers': True,
    'handlers': {
        'file': {
            'level': 'ERROR',
            'class': 'logging.FileHandler',
            'filename': os.path.join(LOG_DIR, 'errors.log'),
        },
        'null': {
            'class': 'logging.NullHandler'
        },
        'default': {
            'class': 'logging.StreamHandler',
            'formatter': 'default',
        },
        'brief': {
            'class': 'logging.StreamHandler',
            'formatter': 'brief'
        },
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'brief'
        },
        'task': {
            'class': 'logging.StreamHandler',
            'formatter': 'task'
        },
        'db': {
            'class': 'logging.handlers.RotatingFileHandler',
            'formatter': 'brief',
            'filename': os.path.join(LOG_DIR, 'db.log'),
            'maxBytes': 1024,
            'backupCount': 3
        },
        'celery': {
            'class': 'logging.handlers.RotatingFileHandler',
            'formatter': 'simple',
            'filename': os.path.join(LOG_DIR, 'celery.log'),
            'maxBytes': 1024 * 1024 * 100,  # 100 mb
        },
    },
    'formatters': {
        'default': {
            'format': '%(message)s'
        },
        'brief': {
            'format': '%(name)-10s | %(message)s'
        },
        'task': {
            '()': lambda : LimesTaskFormatter('%(task_name)-34s | %(levelname)s | %(message)s')
        },
        'simple': {
            'format': '%(levelname)s %(message)s',
            'datefmt': '%y %b %d, %H:%M:%S',
        }
    },
    'loggers': {
        'django': {
            'handlers': ['file'],
            'level': 'ERROR' if DEBUG else 'CRITICAL',
            'propagate': True,
        },
        '': {
            'handlers': ['brief'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': False
        },
        'celery': {
            'handlers': ['celery'],
            'level': 'DEBUG' if DEBUG else 'ERROR',
        },
        'celery.app.trace': {
            'handlers': ['null'],
            'propagate': False,
        },
        'celery.task': {
            'handlers': ['task'],
            'propagate': False
        },
        'celery.worker': {
            'handlers': ['null'],
            'propagate': False,
        },
        # uvicorn creates these before Django configures logging; without a name here disable_existing_loggers
        # silences them, and a crash in the MCP app would leave no traceback.
        'uvicorn': {'handlers': ['brief'], 'level': 'INFO', 'propagate': False},
        'uvicorn.error': {'handlers': ['brief'], 'level': 'INFO', 'propagate': False},
        # The access line carries the query string, and a token sent in a URL must never reach a log: keep it off
        # even though the entrypoint passes --no-access-log (this config would otherwise switch it back on).
        'uvicorn.access': {'handlers': ['null'], 'level': 'CRITICAL', 'propagate': False},
        'django.server': {
            'handlers': ['console'],
            'propagate': False
        },
        'django.db.backends': {
            'handlers': ['db'],
            'level': 'INFO',
            'propagate': False
        },
        'limes.tasks': {
            'handlers': ['task'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': False
        },
        'api.views': {
            'handlers': ['console'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': False
        }
    },
}

'''
File upload settings
'''
DATA_UPLOAD_MAX_NUMBER_FIELDS = None

'''
    Caching Settings
'''
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': env('CACHE_URL', default='redis://redis:6379/1'),
        'TIMEOUT': 60 * 30,
    }
}