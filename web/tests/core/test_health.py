from unittest import mock

from django.test import TestCase


class HealthTest(TestCase):
    def test_ok_without_login(self):
        resp = self.client.get('/healthz')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()['status'], 'ok')

    def test_reports_failed_cache(self):
        with mock.patch('limes.health.cache.set', side_effect=ConnectionError('down')):
            resp = self.client.get('/healthz')
        self.assertEqual(resp.status_code, 503)
        self.assertEqual(resp.json()['failed'], ['cache'])

    def test_reports_failed_database(self):
        with mock.patch('limes.health.connection.cursor', side_effect=ConnectionError('down')):
            resp = self.client.get('/healthz')
        self.assertEqual(resp.status_code, 503)
        self.assertEqual(resp.json()['failed'], ['database'])
