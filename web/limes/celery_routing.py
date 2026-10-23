"""Single source of truth for task queues and time limits."""
SCAN, IO, ORCHESTRATE = 'scan', 'io', 'orchestrate'
MIN, HOUR = 60, 3600
SOFT_MARGIN = 120

TASK_PLAN = {
    # discovery 2 h
    'subdomain_discovery': (SCAN, 2 * HOUR),
    'passive_intel': (SCAN, 1 * HOUR),
    'risk_checks': (SCAN, 1 * HOUR),
    # port scan 2 h
    'port_scan': (SCAN, 2 * HOUR), 'nmap': (SCAN, 2 * HOUR),
    # crawl / probe 2 h
    'fetch_url': (SCAN, 2 * HOUR), 'http_crawl': (SCAN, 2 * HOUR), 'screenshot': (SCAN, 2 * HOUR),
    'run_command': (SCAN, 2 * HOUR),
    # DAST 6 h (assay; no longer blocks on children, so it runs in the scan pool)
    'vulnerability_scan': (SCAN, 6 * HOUR),
    # SAST over crawl artifacts, in-process, 2 h
    'code_audit': (SCAN, 2 * HOUR),
    # parsing, enrichment, notifications 15 min
    'send_notif': (IO, 15 * MIN), 'send_scan_notif': (IO, 15 * MIN), 'send_task_notif': (IO, 15 * MIN),
    'send_file_to_discord': (IO, 15 * MIN),
    'parse_nmap_results': (IO, 15 * MIN), 'geo_localize': (IO, 15 * MIN), 'query_whois': (IO, 15 * MIN),
    'enumerate_ranges': (IO, 15 * MIN),  # network-bound; a 60 s beat tick that holds its own Redis tick lock
    'monitor_assets': (IO, 15 * MIN),  # likewise: contacts targets only through limes.safe_fetch
    'refresh_feeds': (IO, 15 * MIN),  # downloads third-party feeds only (limes.feeds); holds its own Redis tick lock
    'generate_lookalikes': (IO, 15 * MIN), 'lookalike_tick': (IO, 15 * MIN),  # DNS, RDAP, crt.sh only; own tick locks
    'hibp_sync': (IO, 15 * MIN),  # Have I Been Pwned only (limes.hibp); holds its own Redis tick lock
    'remove_duplicate_endpoints': (IO, 15 * MIN),
    'llm_vulnerability_description': (IO, 15 * MIN),
    # orchestration 15 min
    'initiate_scan': (ORCHESTRATE, 15 * MIN), 'initiate_subscan': (ORCHESTRATE, 15 * MIN),
    'report': (ORCHESTRATE, 15 * MIN), 'reap_stuck_scans': (ORCHESTRATE, 15 * MIN),
    'dispatch_due_scans': (ORCHESTRATE, 15 * MIN), 'age_assets': (ORCHESTRATE, 15 * MIN),
    'snapshot_scores': (ORCHESTRATE, 15 * MIN), 'send_digest': (ORCHESTRATE, 15 * MIN),
    'expire_waivers': (ORCHESTRATE, 15 * MIN), 'purge_mcp_logs': (ORCHESTRATE, 15 * MIN),
}

MAX_TIME_LIMIT = max(limit for _, limit in TASK_PLAN.values())


def task_routes():
    return {name: {'queue': queue} for name, (queue, _) in TASK_PLAN.items()}


def task_annotations():
    return {name: {'time_limit': limit, 'soft_time_limit': limit - SOFT_MARGIN}
            for name, (_, limit) in TASK_PLAN.items()}
