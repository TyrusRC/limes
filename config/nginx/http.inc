# The MCP token must never reach a log, even if a client puts it in the query string: log $uri, not $request.
log_format  mcp  '$remote_addr [$time_local] "$request_method $uri" $status $body_bytes_sent';

# Modest per-address cap on /mcp: a token guesser or a runaway agent loop is slowed before it reaches the app.
limit_req_zone  $binary_remote_addr  zone=mcp:10m  rate=20r/s;
