import json
from datetime import timedelta
from unittest import mock

import requests
from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from dashboard import posture
from dashboard.models import Project
from limes import safe_fetch
from limes.alerts.events import is_immediate
from limes.checks import ai, collect, run
from limes.checks.catalogue import AI_PORTS, CHECKS, MAX_AI_PORTS
from startScan.models import Asset

IP = '45.1.1.1'


class Resp:
    def __init__(self, status=200, body=b'', chunks=None):
        self.status_code = status
        self._chunks = chunks if chunks is not None else [body]
        self.closed = False

    def iter_content(self, chunk_size=1):
        yield from self._chunks

    def close(self):
        self.closed = True


def js(obj, status=200):
    return Resp(status, json.dumps(obj).encode())


class Get:
    """Records (url, kwargs); answers from {url suffix after the IP: Resp | Exception}."""
    def __init__(self, answers):
        self.answers, self.calls = answers, []

    def __call__(self, url, **kw):
        self.calls.append((url, kw))
        r = self.answers.get(url.split(IP, 1)[1], requests.exceptions.ConnectionError())
        if isinstance(r, Exception):
            raise r
        return r


def observe(answers, ports):
    get = Get(answers)
    return collect.observe_ai(IP, ports, get, 'ua/1'), get


def by_id(results):
    return {r.check: r for r in results}


def run_ai(answers, ports, complete=True):
    obs, get = observe(answers, ports)
    return by_id(ai.evaluate(obs, complete)), get


class ProbeTest(SimpleTestCase):
    def test_only_known_open_ai_ports_probed(self):
        obs, get = observe({':11434/api/tags': js({'models': []}), ':8888/api': js({'version': '2.14'}),
                            ':8888/api/kernels': js([], 200)}, {22, 11434, 8888, 9999})
        self.assertEqual([u for u, _ in get.calls],
                         [f'http://{IP}:8888/api', f'http://{IP}:8888/api/kernels', f'http://{IP}:11434/api/tags'])
        for _, kw in get.calls:
            self.assertIs(kw['allow_redirects'], False)
            self.assertEqual(kw['headers'], {'User-Agent': 'ua/1'})
            self.assertTrue(kw['stream'])
            self.assertEqual(kw['timeout'], collect.TIMEOUT)

    def test_no_ai_port_means_no_calls(self):
        res, get = run_ai({}, {22, 443})
        self.assertEqual(get.calls, [])
        self.assertEqual({r.status for r in res.values()}, {'not_applicable'})
        self.assertEqual(list(res), ai.IDS)
        obs, _ = observe({}, {22})
        self.assertEqual({r.status for r in ai.evaluate(obs, False)}, {'error'})

    def test_at_most_six_ports(self):
        _, get = run_ai({}, set(AI_PORTS))
        probed = {int(u.split(':')[2].split('/')[0]) for u, _ in get.calls}
        self.assertEqual(probed, set(sorted(AI_PORTS)[:MAX_AI_PORTS]))
        self.assertNotIn(11434, probed)

    def test_body_cap(self):
        seen = []

        def chunks():
            for _ in range(10 * 1024):
                seen.append(1024)
                yield b'x' * 1024
        resp = Resp(200, chunks=chunks())
        res, _ = run_ai({':11434/api/tags': resp}, {11434})
        self.assertLessEqual(sum(seen), collect.BODY_CAP + 1024)
        self.assertEqual(res['net.exposed_ollama'].status, 'not_applicable')
        self.assertTrue(resp.closed)

    def test_hostile_json_does_not_raise(self):
        deep = b'[' * 100000 + b']' * 100000
        res, _ = run_ai({':11434/api/tags': Resp(200, deep), ':8000/v1/models': Resp(200, b'\xff\xfe')}, {11434, 8000})
        self.assertEqual(res['net.exposed_ollama'].status, 'not_applicable')

    def test_connection_refused_vs_error(self):
        res, _ = run_ai({':11434/api/tags': requests.exceptions.ConnectionError(),
                         ':7860/config': requests.exceptions.Timeout()}, {11434, 7860})
        self.assertEqual(res['net.exposed_ollama'].status, 'not_applicable')
        self.assertEqual(res['net.exposed_gradio'].status, 'error')


class EvaluateTest(SimpleTestCase):
    def test_ollama_unauthenticated_fails_with_count_only(self):
        res, _ = run_ai({':11434/api/tags': js({'models': [{'name': 'llama3:<script>'}] * 3})}, {11434})
        r = res['net.exposed_ollama']
        self.assertEqual(r.status, 'fail')
        self.assertEqual(r.evidence, {'port': 11434, 'path': '/api/tags', 'status': 200, 'version': None, 'models': 3})
        self.assertNotIn('llama3', json.dumps(r.evidence))

    def test_openai_api_auth(self):
        path = ':8000/v1/models'
        self.assertEqual(run_ai({path: Resp(401)}, {8000})[0]['net.exposed_openai_api'].status, 'pass')
        r = run_ai({path: js({'object': 'list', 'data': [{}, {}]})}, {8000})[0]['net.exposed_openai_api']
        self.assertEqual((r.status, r.evidence['models']), ('fail', 2))
        self.assertEqual(run_ai({path: Resp(200, b'<html>')}, {8000})[0]['net.exposed_openai_api'].status, 'not_applicable')

    def test_other_openai_ports_share_the_check(self):
        res, _ = run_ai({':1234/v1/models': js({'data': []}), ':4000/v1/models': Resp(403)}, {1234, 4000})
        self.assertEqual(res['net.exposed_openai_api'].evidence['port'], 1234)
        self.assertEqual(res['net.exposed_openai_api'].status, 'fail')

    def test_jupyter_needs_second_get(self):
        api = js({'version': '2.14.0'})
        for second, want in ((Resp(403), 'pass'), (js([]), 'fail'), (Resp(500), 'not_applicable')):
            res, get = run_ai({':8888/api': api, ':8888/api/kernels': second}, {8888})
            self.assertEqual(res['net.exposed_jupyter'].status, want)
            self.assertEqual(len(get.calls), 2)
        res, get = run_ai({':8888/api': Resp(200, b'<html>')}, {8888})
        self.assertEqual(res['net.exposed_jupyter'].status, 'not_applicable')
        self.assertEqual(len(get.calls), 1)
        res, _ = run_ai({':8888/api': api, ':8888/api/kernels': requests.exceptions.Timeout()}, {8888})
        self.assertEqual(res['net.exposed_jupyter'].status, 'error')

    def test_triton_gradio_ray_fingerprints(self):
        res, _ = run_ai({':8000/v2': js({'name': 'triton', 'version': '2.4'}), ':7860/config': js({'version': '4.1', 'components': []}),
                         ':8265/api/version': js({'ray_version': '2.9.0'})}, {8000, 7860, 8265})
        self.assertEqual({k: res[k].status for k in ('net.exposed_triton', 'net.exposed_gradio', 'net.exposed_ray')},
                         {'net.exposed_triton': 'fail', 'net.exposed_gradio': 'fail', 'net.exposed_ray': 'fail'})
        self.assertEqual(res['net.exposed_ray'].evidence['version'], '2.9.0')
        res, _ = run_ai({':8000/v2': js({'name': 'other'}), ':7860/config': js({'version': '4.1'}),
                         ':8265/api/version': Resp(200, b'<html>')}, {8000, 7860, 8265})
        for k in ('net.exposed_triton', 'net.exposed_gradio', 'net.exposed_ray'):
            self.assertEqual(res[k].status, 'not_applicable', k)

    def test_version_is_clipped_and_must_be_text(self):
        res, _ = run_ai({':7860/config': js({'version': 'v' * 200, 'components': []})}, {7860})
        self.assertEqual(len(res['net.exposed_gradio'].evidence['version']), 50)
        res, _ = run_ai({':7860/config': js({'version': {'x': 1}, 'components': []})}, {7860})
        self.assertIsNone(res['net.exposed_gradio'].evidence['version'])

    def test_ai_issue_is_immediate(self):
        self.assertTrue(is_immediate('issue_new', 'net.exposed_ollama', 3))

    def test_catalogue_covers_the_ids(self):
        for i in ai.IDS:
            self.assertTrue(CHECKS[i].provisional)


class RunTest(TestCase):
    def setUp(self):
        self.p = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.root = Asset.objects.create(project=self.p, kind='root_domain', value='example.com', scope_tier='owned_root')

    def ip(self, value):
        return Asset.objects.create(project=self.p, kind='ip', value=value, scope_tier='owned_host')

    def test_probe_goes_through_safe_fetch(self):
        seen = {}
        obs = {'ports': lambda a, n: ({11434: ['naabu']}, True),
               'ai': lambda ip, ports, get, ua: seen.update(ip=ip, ports=set(ports), get=get, ua=ua) or {}}
        for value, public in (('10.0.0.5', False), (IP, True)):
            a = self.ip(value)
            with mock.patch.object(safe_fetch, 'pinned_get', return_value='G') as pg:
                out = run._ip_checks(a, timezone.now(), obs, None)
            ai_rows = by_id(r for r in out if r.check in ai.IDS)
            self.assertEqual(list(ai_rows), ai.IDS)
            if public:
                pg.assert_called_once()
                self.assertEqual(pg.call_args.args, (IP, IP))
                self.assertEqual((seen['get'], seen['ua'], seen['ports']), ('G', 'limes/scan', {11434}))
            else:
                pg.assert_not_called()
                self.assertEqual({r.status for r in ai_rows.values()}, {'error'})
                self.assertIn('reason', ai_rows['net.exposed_ollama'].evidence)

    def test_no_ai_port_no_probe(self):
        def boom(*a):
            raise AssertionError('probed')
        out = run._ip_checks(self.ip(IP), timezone.now(), {'ports': lambda a, n: ({22: ['naabu']}, True), 'ai': boom}, None)
        self.assertEqual({r.status for r in out if r.check in ai.IDS}, {'not_applicable'})

    def test_both_ip_branches_write_ai_rows(self):
        a = self.ip(IP)
        obs = {'ports': lambda a, n: ({}, True), 'mail_dns': lambda r: ({'txt': [], 'dmarc': [], 'mx': []}, {'ds': False, 'caa': False})}
        run.run_asset_checks(a, observers=obs)
        self.assertEqual(set(a.risk_checks.filter(check_id__in=ai.IDS).values_list('status', flat=True)), {'not_applicable'})
        a.risk_checks.all().delete()
        run.run_checks(self.p, self.root, observers=obs)
        self.assertEqual(a.risk_checks.filter(check_id__in=ai.IDS).count(), 6)


class ExposureTest(TestCase):
    def test_exposure_marks_ai_ports(self):
        now = timezone.now()
        p = Project.objects.create(name='p', slug='p', insert_date=now)
        Asset.objects.create(project=p, kind='ip', value=IP, scope_tier='owned_host',
                             enrichment={'internetdb': {'ports': [11434, 8000, 443], 'fetched_at': (now - timedelta(days=1)).isoformat()}})
        rows = {r['port']: r for r in posture.exposure(p, now)['rows']}
        self.assertTrue(rows[11434]['ai'])
        self.assertEqual(rows[11434]['service'], 'ollama')
        self.assertTrue(rows[8000]['ai'])
        self.assertFalse(rows[443]['ai'])
