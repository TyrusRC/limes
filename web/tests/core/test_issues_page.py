from django.contrib.auth.models import User
from django.contrib.auth.signals import user_logged_in
from django.test import TestCase
from django.utils import timezone

from dashboard.models import Project
from dashboard.views import on_user_logged_in


class IssuesPageTest(TestCase):
    def setUp(self):
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        self.client.force_login(User.objects.create_user('u', password='p'))
        Project.objects.create(name='p1', slug='p1', insert_date=timezone.now())
        self.client.get('/scan/p1/issues')  # warm-up (lazy prefs creation)

    def test_page_has_filters_columns_states_and_detail_link_base(self):
        html = self.client.get('/scan/p1/issues').content.decode()
        for needle in ('data-k="severity"', 'data-k="category"', 'data-k="waived"', 'id="tag_chips"', 'Affected assets',
                       'First detected', '>Status<', '>Severity<', 'id="iss_state"', 'limes/issues.js',
                       'data-detail="/scan/p1/issues/0/"', 'aria-busy="true"', 'Informational means a provisional check'):
            self.assertIn(needle, html)
