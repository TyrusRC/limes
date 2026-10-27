"""API checks from limes.api_discovery observations. Pure: no I/O. All three are provisional (limes.checks.catalogue):
tracked and visible, worth no points. Evidence holds status codes, sizes and counts, never response bodies; the few
spec-supplied strings (probed paths) are clipped and untrusted, so every renderer escapes them."""
from limes.checks.catalogue import Result

IDS = ['api.exposed_docs', 'api.no_auth_declared', 'api.unauthenticated_access']
MAX_OPEN_LISTED = 5


def evaluate(obs):
    """Three Results for one api asset. obs = {'protocol': 'graphql'|None, 'spec': {'path', 'status', 'size',
    'schemes': int}, 'probe': None | {'tested': int, 'errors': int, 'open': [{'path', 'status', 'size'}]}}."""
    if obs.get('protocol') == 'graphql' or not obs.get('spec'):
        return [Result(i, 'not_applicable', {}) for i in IDS]  # no specification to judge
    spec, probe = obs['spec'], obs.get('probe')
    out = [Result('api.exposed_docs', 'fail', {'path': spec['path'], 'status': spec['status'], 'size': spec['size']})]
    schemes = spec['schemes']
    out.append(Result('api.no_auth_declared', 'fail' if schemes == 0 else 'pass', {'schemes': schemes}))
    if schemes == 0 or probe is None or probe['tested'] == 0:
        out.append(Result('api.unauthenticated_access', 'not_applicable', {}))
    elif probe['open']:
        out.append(Result('api.unauthenticated_access', 'fail',
                          {'tested': probe['tested'], 'open': probe['open'][:MAX_OPEN_LISTED], 'open_count': len(probe['open'])}))
    elif probe['errors'] * 2 > probe['tested']:  # most of the sweep failed or was cut short: inconclusive, never a pass
        out.append(Result('api.unauthenticated_access', 'error', {'tested': probe['tested'], 'errors': probe['errors']}))
    else:
        out.append(Result('api.unauthenticated_access', 'pass', {'tested': probe['tested'], 'errors': probe['errors']}))
    return out
