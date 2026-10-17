"""Exposed-service checks from a port -> sources map. Pure: no I/O."""
from limes.checks.catalogue import RISKY_PORTS, Result


def evaluate(ports):
    """ports: {port: [source, ...]} of fresh data, or None when there is none (all error)."""
    out = []
    for port, (svc, _sev) in RISKY_PORTS.items():
        check = f'net.exposed_{svc}'
        if ports is None:
            out.append(Result(check, 'error', {}))
        elif port in ports:
            out.append(Result(check, 'fail', {'port': port, 'seen_by': list(ports[port])}))
        else:
            out.append(Result(check, 'pass', {}))
    return out
