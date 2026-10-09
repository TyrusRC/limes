#!/bin/bash
set -euo pipefail
eval "$(python3 /usr/src/app/limes/sizing.py)"
loglevel=info
[ "${DEBUG:-0}" = "1" ] && loglevel=debug
role="${1:?usage: celery-entrypoint.sh scan|io|orchestrate}"
case "$role" in
  scan)
    exec celery -A limes.celery worker -Q scan -n "scan@${HOSTNAME}" -P prefork -O fair \
      --prefetch-multiplier=1 --max-tasks-per-child=20 --autoscale="${SCAN_SLOTS},1" -l "$loglevel" ;;
  io)
    export CELERY_POOL=gevent
    exec celery -A limes.celery worker -Q io -n "io@${HOSTNAME}" -P gevent -c "${IO_CONCURRENCY}" -l "$loglevel" ;;
  orchestrate)
    exec celery -A limes.celery worker -Q orchestrate -n "orchestrate@${HOSTNAME}" -P prefork -c 4 -l "$loglevel" ;;
  *) echo "unknown role $role" >&2; exit 2 ;;
esac
