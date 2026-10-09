import statistics
import time

from django.conf import settings
from django.contrib.auth import BACKEND_SESSION_KEY, HASH_SESSION_KEY, SESSION_KEY, get_user_model
from django.contrib.sessions.backends.db import SessionStore
from django.core.cache import cache
from django.core.management.base import BaseCommand
from django.db import connection
from django.test import Client
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from rolepermissions.roles import assign_role


class Command(BaseCommand):
    help = 'Measure dashboard latency and query count for the "bench" project.'

    def add_arguments(self, parser):
        parser.add_argument('--runs', type=int, default=30)

    def _measure(self, client, url, runs, cold):
        times, queries = [], []
        for _ in range(runs):
            if cold:
                cache.clear()
            with CaptureQueriesContext(connection) as ctx:
                start = time.perf_counter()
                resp = client.get(url)
                times.append((time.perf_counter() - start) * 1000)
            assert resp.status_code == 200, resp.status_code
            queries.append(len(ctx.captured_queries))
        times.sort()
        p95 = times[max(0, int(len(times) * 0.95) - 1)]
        return statistics.median(times), p95, max(queries)

    def handle(self, *args, **opts):
        user, _ = get_user_model().objects.get_or_create(username='bench', defaults={'is_superuser': True, 'is_staff': True})
        assign_role(user, 'sys_admin')
        client = Client()
        # force_login() fires user_logged_in, whose receiver needs request.user; build the session by hand.
        session = SessionStore()
        session[SESSION_KEY] = str(user.pk)
        session[BACKEND_SESSION_KEY] = settings.AUTHENTICATION_BACKENDS[0]
        session[HASH_SESSION_KEY] = user.get_session_auth_hash()
        session.save()
        client.cookies[settings.SESSION_COOKIE_NAME] = session.session_key
        url = reverse('dashboardIndex', kwargs={'slug': 'bench'})
        self.stdout.write('| mode | p50 ms | p95 ms | queries |\n|---|---|---|---|')
        for mode, cold in (('cold', True), ('warm', False)):
            p50, p95, q = self._measure(client, url, opts['runs'], cold)
            self.stdout.write(f'| {mode} | {p50:.0f} | {p95:.0f} | {q} |')
