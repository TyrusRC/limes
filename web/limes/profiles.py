#!/usr/bin/python
import yaml
from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class Profile:
    """Scan profile defining depth, limits, timeouts and assay configuration."""
    name: str
    crawl_depth: int
    crawl_max_pages: int
    naabu_ports: List[str]
    nmap_enabled: bool
    assay_profile: str
    timeouts: Dict[str, int]
    nuclei_severities: List[str]


# Default timeouts (in seconds) for all profiles
DEFAULT_TIMEOUTS = {
    'http_request': 30,
    'port_scan': 300,
    'nmap_scan': 600,
}

# Default nuclei severities
DEFAULT_NUCLEI_SEVERITIES = ['low', 'medium', 'high', 'critical']

# Profile presets
PROFILES = {
    'quick': Profile(
        name='quick',
        crawl_depth=1,
        crawl_max_pages=50,
        naabu_ports=['top-100'],
        nmap_enabled=False,
        assay_profile='quick',
        timeouts=DEFAULT_TIMEOUTS.copy(),
        nuclei_severities=['high', 'critical'],
    ),
    'normal': Profile(
        name='normal',
        crawl_depth=2,
        crawl_max_pages=200,
        naabu_ports=['top-1000'],
        nmap_enabled=True,
        assay_profile='normal',
        timeouts=DEFAULT_TIMEOUTS.copy(),
        nuclei_severities=DEFAULT_NUCLEI_SEVERITIES.copy(),
    ),
    'thorough': Profile(
        name='thorough',
        crawl_depth=3,
        crawl_max_pages=500,
        naabu_ports=['1-65535'],
        nmap_enabled=True,
        assay_profile='thorough',
        timeouts={**DEFAULT_TIMEOUTS, 'port_scan': 600, 'nmap_scan': 1200},
        nuclei_severities=DEFAULT_NUCLEI_SEVERITIES.copy(),
    ),
    'passive': Profile(
        name='passive',
        crawl_depth=1,
        crawl_max_pages=50,
        naabu_ports=[],
        nmap_enabled=False,
        assay_profile='passive',
        timeouts=DEFAULT_TIMEOUTS.copy(),
        nuclei_severities=['medium', 'high', 'critical'],
    ),
}


def resolve_profile(name: str) -> Profile:
    """
    Resolve a profile by name.

    Args:
        name: Profile name (quick, normal, thorough, passive)

    Returns:
        Profile object, defaults to 'normal' if name is unknown
    """
    return PROFILES.get(name, PROFILES['normal'])


def map_engine_to_profile(yaml_configuration: str) -> str:
    """
    Map a legacy engine YAML configuration to a profile name.

    Args:
        yaml_configuration: YAML string defining legacy engine configuration

    Returns:
        Profile name (quick, normal, thorough, passive)
        Returns 'normal' if YAML is invalid or cannot be parsed
    """
    try:
        config = yaml.safe_load(yaml_configuration)
        if not isinstance(config, dict):
            return 'normal'
    except Exception:
        # Garbage YAML or parsing error
        return 'normal'

    # Check for specific stage combinations
    has_subdomain_discovery = 'subdomain_discovery' in config
    has_port_scan = 'port_scan' in config
    has_fetch_url = 'fetch_url' in config
    has_vulnerability_scan = 'vulnerability_scan' in config
    has_screenshot = 'screenshot' in config

    # Thorough: has vulnerability_scan + screenshot
    if has_vulnerability_scan and has_screenshot:
        return 'thorough'

    # Passive: discovery-only (only subdomain_discovery)
    if has_subdomain_discovery and not has_port_scan and not has_fetch_url and not has_vulnerability_scan:
        return 'passive'

    # Normal: has port_scan + fetch_url, or any other combination
    # (includes default case)
    return 'normal'
