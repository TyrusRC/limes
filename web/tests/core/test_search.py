from django.contrib.auth.models import User
from django.contrib.auth.signals import user_logged_in
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from dashboard.models import Project
from dashboard.views import on_user_logged_in
from startScan.models import Asset, TrackedIssue


class SearchApiTest(TestCase):
    def setUp(self):
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        self.user = User.objects.create_user('s1', password='p')
        self.p1 = Project.objects.create(name='p1', slug='p1', insert_date=timezone.now())
        self.p2 = Project.objects.create(name='p2', slug='p2', insert_date=timezone.now())
        self.a1 = Asset.objects.create(project=self.p1, kind='hostname', value='app.example.com', scope_tier='owned_host')
        self.a2 = Asset.objects.create(project=self.p2, kind='hostname', value='app.other.com', scope_tier='owned_host')
        self.weird = Asset.objects.create(project=self.p1, kind='hostname', value='<img src=x>.example.com', scope_tier='owned_host')
        TrackedIssue.objects.create(project=self.p1, asset=self.a1, key='exposed-panel', source='finding', severity=3)
        TrackedIssue.objects.create(project=self.p2, asset=self.a2, key='exposed-panel', source='finding', severity=3)
        self.c = APIClient()
        self.c.force_login(self.user)

    def get(self, **params):
        return self.c.get('/api/search/', params)

    def test_results_are_project_scoped(self):
        r = self.get(project='p1', query='app.').json()['results']
        self.assertEqual([a['value'] for a in r['assets']], ['app.example.com'])
        r = self.get(project='p1', query='exposed').json()['results']
        self.assertEqual([(i['asset'], i['title']) for i in r['issues']], [('app.example.com', 'exposed-panel')])
        self.assertEqual(self.get(project='p2', query='example').json()['results']['assets'], [])

    def test_unknown_project_404_and_short_query_400(self):
        self.assertEqual(self.get(project='nope', query='app').status_code, 404)
        self.assertEqual(self.get(query='app').status_code, 404)
        self.assertEqual(self.get(project='p1', query='a').status_code, 400)
        self.assertEqual(self.get(project='p1', query='x' * 201).status_code, 400)

    def test_query_is_literal_text(self):
        self.assertEqual(self.get(project='p1', query='%%').json()['results']['assets'], [])
        self.assertEqual(self.get(project='p1', query='a_p').json()['results']['assets'], [])

    def test_anonymous_refused(self):
        self.assertIn(APIClient().get('/api/search/', {'project': 'p1', 'query': 'app'}).status_code, (302, 401, 403))

    def test_page_reflects_the_query_escaped(self):
        self.client.force_login(self.user)
        html = self.client.get(reverse('search', args=['p1']), {'query': '"><script>alert(1)</script>'}).content.decode()
        self.assertNotIn('<script>alert(1)</script>', html)
