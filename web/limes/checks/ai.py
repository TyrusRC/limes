"""Exposed AI-service checks from collect.observe_ai observations. Pure: no I/O. Evidence carries counts and a
clipped version only, never model names or bodies (they are untrusted text)."""
from limes.checks.catalogue import Result

FINGERPRINTS = {'ollama': '/api/tags', 'openai_api': '/v1/models', 'triton': '/v2', 'gradio': '/config',
                'jupyter': '/api', 'ray': '/api/version'}
IDS = [f'net.exposed_{s}' for s in FINGERPRINTS]
_RANK = {'fail': 0, 'error': 1, 'pass': 2, 'not_applicable': 3}


def _text(v):
    return v[:50] if isinstance(v, str) else None


def _judge(svc, probe):
    """(status, version, models) for one probe."""
    st, body = probe['status'], probe['json']
    if st == 'error':
        return 'error', None, None
    if svc == 'jupyter':
        if not isinstance(body, dict) or 'version' not in body:
            return 'not_applicable', None, None
        second = probe.get('second') or {}
        ver = _text(body['version'])
        if second.get('status') == 'error':
            return 'error', ver, None
        if second.get('status') == 200 and isinstance(second.get('json'), list):
            return 'fail', ver, None
        return ('pass' if second.get('status') in (401, 403) else 'not_applicable'), ver, None
    if st in (401, 403):
        return 'pass', None, None
    if st != 200 or body is None:
        return 'not_applicable', None, None
    d = body if isinstance(body, dict) else {}
    if svc == 'ollama' and isinstance(d.get('models'), list):
        return 'fail', None, len(d['models'])
    if svc == 'openai_api' and isinstance(d.get('data'), list):
        return 'fail', None, len(d['data'])
    if svc == 'triton' and d.get('name') == 'triton':
        return 'fail', _text(d.get('version')), None
    if svc == 'gradio' and 'version' in d and 'components' in d:
        return 'fail', _text(d['version']), None
    if svc == 'ray' and ('ray_version' in d or 'version' in d):
        return 'fail', _text(d.get('ray_version', d.get('version'))), None
    return 'not_applicable', None, None


def evaluate(obs, complete):
    """One Result per AI check, in catalogue order. A service seen on several ports reports its worst: fail, then
    error (unknown beats a pass elsewhere), then pass."""
    out = []
    for svc, path in FINGERPRINTS.items():
        check, best = f'net.exposed_{svc}', None
        for port in sorted(obs):
            probe = obs[port].get(svc)
            if probe is None:
                continue
            status, version, models = _judge(svc, probe)
            ev_path = '/api/kernels' if svc == 'jupyter' and status in ('fail', 'pass') else path
            code = (probe.get('second') or {}).get('status') if svc == 'jupyter' and ev_path != path else probe['status']
            if best is None or _RANK[status] < _RANK[best[0]]:
                best = (status, {'port': port, 'path': ev_path, 'status': code if isinstance(code, int) else None,
                                 'version': version, 'models': models})
        if best is None:
            out.append(Result(check, 'not_applicable' if complete else 'error', {}))
        else:
            out.append(Result(check, best[0], {} if best[0] in ('not_applicable', 'error') else best[1]))
    return out
