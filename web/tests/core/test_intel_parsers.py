import json
import os

from django.test import SimpleTestCase

from limes.intel import crtsh, internetdb, ripestat

FX = os.path.join(os.path.dirname(__file__), 'fixtures')


def load(name):
    with open(os.path.join(FX, name)) as f:
        return json.load(f)


class CrtshTest(SimpleTestCase):
    def test_url(self):
        self.assertEqual(crtsh.build_url('example.com'),
                         'https://crt.sh/?q=%25.example.com&output=json&exclude=expired')

    def test_parse(self):
        self.assertEqual(crtsh.parse(load('crtsh_sample.json')), [
            {'id': 101, 'names': ['example.com', 'www.example.com']},
            {'id': 102, 'names': ['api.example.com', 'shop.example-brand.net', 'example-brand.net', 'example.org']},
            {'id': 103, 'names': ['www.example.com']},
        ])

    def test_parse_junk(self):
        for junk in (None, {}, 'html', [None, 1]):
            self.assertEqual(crtsh.parse(junk), [])


class InternetDbTest(SimpleTestCase):
    def test_url(self):
        self.assertEqual(internetdb.build_url('203.0.114.7'), 'https://internetdb.shodan.io/203.0.114.7')

    def test_parse(self):
        self.assertEqual(internetdb.parse(load('internetdb_sample.json')), {
            'ports': [80, 443], 'cpes': ['cpe:/a:nginx:nginx:1.18.0'], 'vulns': ['CVE-2021-23017'],
            'tags': ['cloud'], 'hostnames': ['mail.partner-co.com', 'www.example.com']})

    def test_parse_404_and_junk(self):
        self.assertIsNone(internetdb.parse(load('internetdb_404.json')))
        for junk in (None, [], 'x'):
            self.assertIsNone(internetdb.parse(junk))


class RipestatTest(SimpleTestCase):
    def test_urls(self):
        self.assertEqual(ripestat.network_info_url('104.16.1.1'),
                         'https://stat.ripe.net/data/network-info/data.json?resource=104.16.1.1&sourceapp=limes')
        self.assertEqual(ripestat.as_overview_url('13335'),
                         'https://stat.ripe.net/data/as-overview/data.json?resource=AS13335&sourceapp=limes')

    def test_parse(self):
        self.assertEqual(ripestat.parse_network_info(load('ripestat_network_info.json')),
                         {'asn': '13335', 'prefix': '104.16.0.0/13'})
        self.assertEqual(ripestat.parse_as_overview(load('ripestat_as_overview.json')),
                         {'holder': 'CLOUDFLARENET - Cloudflare, Inc., US'})

    def test_parse_junk(self):
        for junk in (None, {}, {'data': None}, {'data': {'asns': 'x', 'prefix': 5}}):
            self.assertEqual(ripestat.parse_network_info(junk), {'asn': None, 'prefix': None})
            self.assertEqual(ripestat.parse_as_overview(junk), {'holder': None})
