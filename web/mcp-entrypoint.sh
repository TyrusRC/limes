#!/bin/bash
set -euo pipefail
exec uvicorn limes.mcp.asgi:application --host 0.0.0.0 --port 8001 --workers "${MCP_WORKERS:-2}" --no-access-log --timeout-graceful-shutdown 10
