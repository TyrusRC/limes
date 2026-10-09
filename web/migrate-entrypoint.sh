#!/bin/bash
set -euo pipefail
python3 manage.py migrate --noinput
python3 manage.py collectstatic --no-input --clear
python3 manage.py loaddata fixtures/default_scan_engines.yaml --app scanEngine.EngineType
python3 manage.py loaddata fixtures/default_keywords.yaml --app scanEngine.InterestingLookupModel
