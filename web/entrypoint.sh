#!/bin/bash
set -euo pipefail
eval "$(python3 /usr/src/app/limes/sizing.py)"
exec gunicorn limes.wsgi:application \
    --bind 0.0.0.0:8000 \
    --workers "${WEB_WORKERS}" --worker-class gthread --threads 4 \
    --timeout 300 --access-logfile - --error-logfile -
