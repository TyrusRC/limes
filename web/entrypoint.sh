#!/bin/bash
set -euo pipefail
eval "$(python3 /usr/src/app/limes/sizing.py)"
# NOTE: DataTables sends every column spec in the GET query (~6 KB for the
# vulnerability table). 8190 is gunicorn's maximum and matches nginx's 8 KB
# header buffer; a wider table would need server-side POST instead.
exec gunicorn limes.wsgi:application \
    --bind 0.0.0.0:8000 \
    --workers "${WEB_WORKERS}" --worker-class gthread --threads 4 \
    --timeout 300 --access-logfile - --error-logfile - \
    --limit-request-line 8190
