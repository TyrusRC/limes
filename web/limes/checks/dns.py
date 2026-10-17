"""DNSSEC and CAA checks from one observation. Pure: no I/O."""
from limes.checks.catalogue import CHECKS, Result

IDS = [i for i in CHECKS if i.startswith('dns.')]


def _missing(check, present):
    if present == 'error':
        return Result(check, 'error', {})
    return Result(check, 'pass' if present else 'fail', {})


def evaluate(obs):
    return [_missing('dns.dnssec_missing', obs['ds']), _missing('dns.caa_missing', obs['caa'])]
