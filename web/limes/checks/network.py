"""Exposed-service checks from a port -> sources map. Pure: no I/O."""
from limes.checks.catalogue import RISKY_PORTS, Result


def evaluate(ports, complete):
    """ports: {port: [source, ...]}; complete: the data vouches for absent ports (fresh InternetDB).
    A seen risky port fails from any source; an unseen one passes only when the data is complete."""
    out = []
    for port, (svc, _sev) in RISKY_PORTS.items():
        check = f'net.exposed_{svc}'
        if port in ports:
            out.append(Result(check, 'fail', {'port': port, 'seen_by': list(ports[port])}))
        else:
            out.append(Result(check, 'pass' if complete else 'error', {}))
    return out
