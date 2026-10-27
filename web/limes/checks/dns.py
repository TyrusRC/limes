"""DNSSEC and CAA checks from one observation. Pure: no I/O."""
from limes.checks.catalogue import CHECKS, Result

IDS = [i for i in CHECKS if i.startswith('dns.')]


def _missing(check, present):
    if present == 'error':
        return Result(check, 'error', {})
    return Result(check, 'pass' if present else 'fail', {})


def evaluate(obs):
    return [_missing('dns.dnssec_missing', obs['ds']), _missing('dns.caa_missing', obs['caa'])]


def evaluate_ns(obs):
    """dns.dangling_ns. obs = {'ns': [name, ...] | 'error', 'gone': [name, ...], 'unknown': int}: `gone` are name servers
    whose name is NXDOMAIN (an expired or deleted name anyone could register), `unknown` those whose lookup failed.
    Evidence keeps counts and the dead names (the owner's own delegation, clipped)."""
    check, ns = 'dns.dangling_ns', obs['ns']
    if ns == 'error':
        return Result(check, 'error', {})
    if not ns:
        return Result(check, 'not_applicable', {})
    if obs['gone']:
        return Result(check, 'fail', {'count': len(obs['gone']), 'of': len(ns),
                                      'nameservers': [n[:255] for n in obs['gone'][:5]],
                                      'expected': 'every name server in the delegation resolves',
                                      'actual': f"{len(obs['gone'])} of {len(ns)} do not exist (NXDOMAIN)"})
    if obs['unknown']:
        return Result(check, 'error', {'reason': 'could not look up every name server'})
    return Result(check, 'pass', {})
