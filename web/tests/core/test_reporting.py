import csv
import io
import os
import stat
import tempfile
from datetime import datetime, timedelta, timezone as dt_tz
from unittest import mock

from django.contrib.auth.models import User
from django.contrib.auth.signals import user_logged_in
from django.core import mail
from django.core.cache import cache
from django.db import connection
from django.test import override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from rolepermissions.roles import assign_role

from dashboard.stats import asm_stats
from dashboard.views import on_user_logged_in
from limes.alerts.issues import sync_issues
from reporting import delivery, exports, sched, store, summary, validate
from reporting.models import ReportRun, ReportSchedule
from startScan.models import Asset, ScoreSnapshot, Tag, Technology, TrackedIssue, Vulnerability
from tests.core.test_dashboard_stats import Base

X = '<img src=x onerror=alert(1)>'
ESCAPED = '&lt;img src=x onerror=alert(1)&gt;'


class ReportBase(Base):
    def setUp(self):
        super().setUp()
        user_logged_in.disconnect(on_user_logged_in)
        self.addCleanup(user_logged_in.connect, on_user_logged_in)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        o = override_settings(LIMES_RESULTS=tmp.name)
        o.enable()
        self.addCleanup(o.disable)
        self.results = tmp.name
        self.admin = User.objects.create_user('adm', password='p')
        assign_role(self.admin, 'sys_admin')
        self.auditor = User.objects.create_user('aud', password='p')
        assign_role(self.auditor, 'auditor')
        self.client.force_login(self.admin)

    def vuln(self, asset, name, sev=3, project=None):
        self.vulns([(asset, name, sev)], project)

    def vulns(self, rows, project=None):
        """Findings of one scan (only each root's latest scan counts)."""
        scan = self.scan('y.com' if project is self.other else 'x.com', vuln=True)
        for asset, name, sev in rows:
            Vulnerability.objects.create(scan_history=scan, asset=asset, name=name, template_id=name, severity=sev, open_status=True)
        sync_issues(project or self.p, now=self.now)

    def tag(self, asset, name='prod'):
        t, _ = Tag.objects.get_or_create(project=asset.project, name=name)
        asset.tags.add(t)

    def sched(self, **kw):
        kw.setdefault('project', self.p)
        kw.setdefault('name', 'Monthly')
        kw.setdefault('frequency', 'monthly')
        kw.setdefault('created_at', self.now - timedelta(days=400))
        return ReportSchedule.objects.create(**kw)

    def run_for(self, project=None, **kw):
        project = project or self.p
        name = store.write(project, '<html>ok</html>')
        return ReportRun.objects.create(project=project, name='r', file=name, size=15, **kw)


class CellTest(ReportBase):
    def test_formula_prefixes_are_neutralised(self):
        for bad in ('=1+1', '+1', '-1', '@SUM(A1)', '\tx', '\rx', "=cmd|' /C calc'!A0"):
            self.assertEqual(exports.cell(bad), "'" + bad, bad)
        for fine in ('plain', 'a=b', '', "'quoted"):
            self.assertEqual(exports.cell(fine), fine)
        self.assertEqual(exports.cell(-5), -5)
        self.assertIsNone(exports.cell(None) or None)


class ExportTest(ReportBase):
    def get(self, name, slug='p', **q):
        return self.client.get(reverse(name, kwargs={'slug': slug}), q)

    def rows(self, r):
        return list(csv.reader(io.StringIO(r.content.decode())))

    def test_issues_csv_scoped_escaped_and_tagged(self):
        a = self.asset('=HYPERLINK("http://e").x.com')
        self.tag(a, 'prod')
        self.vuln(a, '=2+2 evil', 3)
        o = self.asset('o.y.com', project=self.other)
        self.vuln(o, 'other-secret', 4, project=self.other)
        r = self.get('export_issues')
        self.assertEqual(r.status_code, 200)
        self.assertIn('text/csv', r['Content-Type'])
        self.assertIn('attachment', r['Content-Disposition'])
        rows = self.rows(r)
        self.assertEqual(rows[0][:3], ['asset', 'category', 'issue'])
        body = r.content.decode()
        self.assertNotIn('other-secret', body)
        self.assertEqual(len(rows), 2)
        self.assertTrue(rows[1][0].startswith("'="), rows[1][0])
        self.assertIn("'=2+2 evil", body)
        self.assertIn('prod', rows[1])

    def test_issues_csv_truncation_is_stated(self):
        a = self.asset('a.x.com')
        self.vulns([(a, f'v{i}', 3) for i in range(3)])
        with mock.patch.object(exports, 'EXPORT_CAP', 2):
            r = self.get('export_issues')
        self.assertEqual(r['X-Limes-Truncated'], '1')
        self.assertIn('truncated', self.rows(r)[-1][0])

    def test_assets_csv_has_tags_and_is_project_scoped(self):
        a = self.asset('a.x.com')
        self.tag(a, 'prod')
        self.tag(a, 'edge')
        self.asset('o.y.com', project=self.other)
        rows = self.rows(self.get('export_assets'))
        values = {r[0]: r for r in rows[1:]}
        self.assertNotIn('o.y.com', values)
        self.assertEqual(values['a.x.com'][rows[0].index('tags')], 'edge; prod')

    def test_tag_filter_and_unknown_slug(self):
        a, b = self.asset('a.x.com'), self.asset('b.x.com')
        self.tag(a, 'prod')
        names = [r[0] for r in self.rows(self.get('export_assets', tag='prod'))[1:]]
        self.assertEqual(names, ['a.x.com'])
        self.assertEqual(self.get('export_assets', slug='nope').status_code, 404)

    def test_anonymous_is_sent_to_login(self):
        self.client.cookies.clear()
        r = self.get('export_assets')
        self.assertEqual(r.status_code, 302)
        self.assertIn('login', r['Location'])


class SummaryTest(ReportBase):
    def test_headline_is_plain_sentences(self):
        a = self.asset('a.x.com')
        self.vuln(a, 'bad', 4)
        d = summary.build(self.p, days=90, now=self.now)
        text = d['headline']
        self.assertIn('grade', text)
        self.assertNotIn('{', text)
        self.assertIn('critical', text)

    def test_headline_without_data_does_not_crash(self):
        d = summary.build(self.p, days=30, now=self.now)
        self.assertIn('not', d['headline'].lower())

    def test_days_and_tag_validated(self):
        self.assertEqual(summary.build(self.p, days=7, now=self.now)['days'], 90)
        d = summary.build(self.p, tag='nosuch', now=self.now)
        self.assertTrue(d['tag_missing'])
        self.assertEqual(d['risks']['rows'], [])

    def test_tag_filter_narrows_risks(self):
        a, b = self.asset('a.x.com'), self.asset('b.x.com')
        self.tag(a, 'prod')
        self.vulns([(a, 'in-tag', 3), (b, 'out-of-tag', 3)])
        d = summary.build(self.p, tag='prod', now=self.now)
        self.assertEqual([r['title'] for r in d['risks']['rows']], ['in-tag'])
        self.assertEqual(d['tags'][0]['name'], 'prod')
        self.assertEqual(len(summary.build(self.p, now=self.now)['risks']['rows']), 2)

    def test_risks_are_capped_and_flagged_truncated(self):
        a = self.asset('a.x.com')
        self.vulns([(a, f'v{i}', 3) for i in range(4)])
        with mock.patch.object(summary, 'TOP_RISKS', 3):
            r = summary.build(self.p, now=self.now)['risks']
        self.assertEqual((len(r['rows']), r['total'], r['truncated']), (3, 4, True))

    def test_remediation_windows_and_trend(self):
        a = self.asset('a.x.com')
        self.vuln(a, 'old', 3)
        TrackedIssue.objects.filter(key='old').update(status='fixed', fixed_at=self.now - timedelta(days=5),
                                                      first_seen=self.now - timedelta(days=60))
        ScoreSnapshot.objects.create(project=self.p, date=(self.now - timedelta(days=60)).date(), version='v', score=500, grade='C')
        d = summary.build(self.p, days=90, now=self.now)
        w = {r['days']: r for r in d['progress']}
        self.assertEqual((w[30]['fixed'], w[30]['opened']), (1, 0))
        self.assertEqual((w[90]['fixed'], w[90]['opened']), (1, 1))
        self.assertEqual(d['score']['delta_from'], 500)

    def page(self, slug='p', **q):
        return self.client.get(reverse('executive_summary', kwargs={'slug': slug}), q)

    def test_page_escapes_hostile_data(self):
        a = self.asset(X + '.x.com')
        self.vuln(a, X, 3)
        r = self.page()
        self.assertEqual(r.status_code, 200)
        html = r.content.decode()
        self.assertNotIn(X, html)
        self.assertIn(ESCAPED, html)

    def test_page_other_slug_and_filters(self):
        self.assertEqual(self.page(slug='nope').status_code, 404)
        self.assertEqual(self.page(days='abc', tag='%00').status_code, 200)

    def test_query_count_does_not_grow_with_the_estate(self):
        def estate(lo, hi):
            hosts = [self.asset(f'h{i}.x.com') for i in range(lo, hi)]
            for i, a in enumerate(hosts):
                self.tag(a, f't{i % 3}')
                a.technologies.add(Technology.objects.get_or_create(name=f'tech{i}')[0])
            self.vulns([(a, f'v{i}', 2 + i % 2) for i, a in enumerate(hosts, lo)])

        def count():
            cache.clear()
            with CaptureQueriesContext(connection) as q:
                self.assertEqual(self.page(days='365', tag='t1').status_code, 200)
                self.assertEqual(self.page().status_code, 200)
            return len(q)
        estate(0, 3)
        self.page()  # warm-up (lazy prefs)
        small = count()
        estate(3, 40)
        self.assertEqual(count(), small)  # no query per asset, issue or tag
        self.assertLess(small, 300)


class ValidateTest(ReportBase):
    def test_recipients(self):
        self.assertEqual(validate.recipients('a@example.com, B@Example.com\nc@example.org'),
                         ['a@example.com', 'b@example.com', 'c@example.org'])
        for bad in ('not-an-email', 'a@example.com\r\nBcc: evil@example.com', 'a@b', 'x@example.com;y@example.com y',
                    ','.join(f'u{i}@example.com' for i in range(21)), 'a@example.com,' + 'b' * 300 + '@example.com'):
            with self.assertRaises(validate.ReportError, msg=bad):
                validate.recipients(bad)
        self.assertEqual(len(validate.recipients(','.join(f'u{i}@example.com' for i in range(20)))), 20)

    def test_name_rejects_control_characters(self):
        self.assertEqual(validate.name('  Board pack  '), 'Board pack')
        for bad in ('', 'x' * 101, 'a\r\nBcc: x', 'a\tb', 'a\x00b'):
            with self.assertRaises(validate.ReportError, msg=repr(bad)):
                validate.name(bad)

    def test_subject_cannot_carry_a_newline(self):
        s = delivery.subject(self.p, 'Weekly\r\nBcc: evil@example.com')
        self.assertNotIn('\n', s)
        self.assertNotIn('\r', s)


class PeriodTest(ReportBase):
    def test_keys_and_due_moments(self):
        s = self.sched(frequency='weekly', weekday=2, hour=8)
        now = datetime(2026, 10, 28, 9, 0, tzinfo=dt_tz.utc)  # a Wednesday
        key, due = sched.current_period(s, now)
        self.assertEqual(key, '2026-W44')
        self.assertEqual(due, datetime(2026, 10, 28, 8, 0, tzinfo=dt_tz.utc))
        s = self.sched(frequency='monthly', day_of_month=15, hour=6)
        self.assertEqual(sched.current_period(s, now), ('2026-10', datetime(2026, 10, 15, 6, tzinfo=dt_tz.utc)))
        s = self.sched(frequency='quarterly', day_of_month=2, hour=0)
        self.assertEqual(sched.current_period(s, now), ('2026-Q4', datetime(2026, 10, 2, 0, tzinfo=dt_tz.utc)))


class GenerateTest(ReportBase):
    NOW = datetime(2026, 10, 28, 9, 0, tzinfo=dt_tz.utc)

    def test_due_schedule_runs_once_per_period(self):
        s = self.sched(day_of_month=1, hour=6)
        self.assertEqual(sched.run_due(self.NOW), 1)
        self.assertEqual(sched.run_due(self.NOW + timedelta(hours=3)), 0)  # same period: no duplicate
        self.assertEqual(ReportRun.objects.filter(schedule=s).count(), 1)
        self.assertEqual(len(os.listdir(os.path.join(self.results, 'reports', str(self.p.id)))), 1)
        nxt = self.NOW + timedelta(days=10)
        self.assertEqual(sched.run_due(nxt), 1)  # November
        self.assertEqual(ReportRun.objects.filter(schedule=s).count(), 2)

    def test_race_on_the_unique_period_leaves_one_row_and_no_orphan_file(self):
        s = self.sched()
        ReportRun.objects.create(project=self.p, schedule=s, name='x', file='a' * 32 + '.html', period_key='2026-10')
        with mock.patch.object(sched, '_exists', return_value=False):  # the other worker finished after our check
            self.assertEqual(sched.run_due(self.NOW), 0)
        self.assertEqual(ReportRun.objects.count(), 1)
        self.assertFalse(os.path.isdir(os.path.join(self.results, 'reports', str(self.p.id))) and
                         os.listdir(os.path.join(self.results, 'reports', str(self.p.id))))

    def test_not_due_disabled_new_or_switched_off(self):
        self.sched(day_of_month=20)  # 20th is after NOW's 9:00 on the 28th? no: it is before, so due
        self.sched(name='later', day_of_month=28, hour=23)  # not yet
        self.sched(name='off', enabled=False)
        self.sched(name='new', created_at=self.NOW)  # created after this period's due moment
        self.assertEqual(sched.run_due(self.NOW), 1)
        with override_settings(REPORTS_ENABLED=False):
            ReportRun.objects.all().delete()
            self.assertEqual(sched.run_due(self.NOW), 0)

    def test_files_are_private_and_snapshot_is_escaped_and_self_contained(self):
        a = self.asset(X + '.x.com')
        self.vuln(a, X, 4)
        run = sched.generate(self.p, name='Board', now=self.NOW, trigger='manual')
        path = store.path(run)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(path)).st_mode), 0o700)
        html = open(path, encoding='utf-8').read()
        self.assertNotIn(X, html)
        self.assertIn(ESCAPED, html)
        self.assertNotIn('<script', html.lower())
        self.assertNotIn('http://', html)
        self.assertNotIn('https://', html)
        self.assertEqual(run.size, os.path.getsize(path))

    def test_manual_runs_do_not_collide(self):
        s = self.sched()
        for _ in range(2):
            sched.generate(self.p, name='n', schedule=s, now=self.NOW, trigger='manual')
        self.assertEqual(ReportRun.objects.count(), 2)


class DeliveryTest(ReportBase):
    NOW = GenerateTest.NOW

    def test_platform_only_sends_nothing(self):
        run = sched.generate(self.p, name='n', schedule=self.sched(delivery='platform'), now=self.NOW)
        self.assertEqual(mail.outbox, [])
        self.assertEqual(run.delivery_note, 'In-platform only')

    @override_settings(EMAIL_BACKEND='django.core.mail.backends.smtp.EmailBackend', EMAIL_HOST='localhost')
    def test_email_not_configured_still_keeps_the_copy(self):
        s = self.sched(delivery='email', recipients=['a@example.com'])
        run = sched.generate(self.p, name='n', schedule=s, now=self.NOW)
        self.assertEqual(run.delivery_note, 'Email not configured: in-platform copy only')
        self.assertTrue(os.path.exists(store.path(run)))

    def test_email_goes_one_message_per_recipient_without_the_snapshot(self):
        s = self.sched(delivery='email', recipients=['a@example.com', 'b@example.com'], name='Board\r\nBcc: z@example.com')
        run = sched.generate(self.p, name=s.name, schedule=s, now=self.NOW)
        self.assertEqual(len(mail.outbox), 2)
        self.assertEqual([m.to for m in mail.outbox], [['a@example.com'], ['b@example.com']])
        for m in mail.outbox:
            self.assertNotIn('\n', m.subject)
            self.assertEqual(m.bcc, [])
            self.assertNotIn('<html', m.body.lower())
            self.assertIn('Reports', m.body)
        self.assertEqual(run.delivery_note, 'Emailed to 2 recipients')

    def test_email_failure_is_recorded_not_raised(self):
        s = self.sched(delivery='email', recipients=['a@example.com'])
        with mock.patch('django.core.mail.EmailMessage.send', side_effect=OSError('smtp://user:pw@host')):
            run = sched.generate(self.p, name='n', schedule=s, now=self.NOW)
        self.assertEqual(run.delivery_note, 'Email failed: in-platform copy kept')
        self.assertNotIn('pw', run.delivery_note)


class DownloadTest(ReportBase):
    def dl(self, run, slug='p'):
        return self.client.get(reverse('report_download', kwargs={'slug': slug, 'run_id': run.id}))

    def test_download_is_attachment_with_hardened_headers(self):
        run = self.run_for()
        r = self.dl(run)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(b''.join(r.streaming_content), b'<html>ok</html>')
        self.assertIn('attachment', r['Content-Disposition'])
        self.assertEqual(r['X-Content-Type-Options'], 'nosniff')
        self.assertIn('no-store', r['Cache-Control'])
        self.assertIn("default-src 'none'", r['Content-Security-Policy'])

    def test_other_projects_run_is_404_under_either_slug(self):
        run = self.run_for(self.other)
        self.assertEqual(self.dl(run, 'p').status_code, 404)
        self.assertEqual(self.dl(run, 'o').status_code, 200)  # its own project: fine
        mine = self.run_for()
        self.assertEqual(self.dl(mine, 'o').status_code, 404)

    def test_path_traversal_and_foreign_files_refused(self):
        secret = os.path.join(self.results, 'secret.html')
        open(secret, 'w').write('s3cret')
        for evil in ('../../secret.html', '../secret.html', '/etc/passwd', 'a/b.html', ('a' * 32) + '.html/../../x',
                     ('A' * 32) + '.html', 'x' * 32 + '.html'):
            run = self.run_for()
            ReportRun.objects.filter(pk=run.pk).update(file=evil)
            self.assertEqual(self.dl(ReportRun.objects.get(pk=run.pk)).status_code, 404, evil)

    def test_symlink_out_of_the_reports_dir_refused(self):
        run = self.run_for()
        p = store.path(run)
        os.remove(p)
        secret = os.path.join(self.results, 'secret.html')
        open(secret, 'w').write('s3cret')
        os.symlink(secret, p)
        self.assertEqual(self.dl(run).status_code, 404)

    def test_missing_file_is_404_and_anonymous_redirected(self):
        run = self.run_for()
        os.remove(store.path(run))
        self.assertEqual(self.dl(run).status_code, 404)
        self.client.cookies.clear()
        self.assertEqual(self.dl(run).status_code, 302)


class ScheduleViewTest(ReportBase):
    def form(self, **kw):
        base = {'name': 'Board pack', 'frequency': 'weekly', 'weekday': '1', 'day_of_month': '1', 'hour': '7', 'tag': '',
                'delivery': 'platform', 'recipients': '', 'enabled': 'on'}
        base.update(kw)
        return base

    def url(self, name, **kw):
        return reverse(name, kwargs={'slug': kw.pop('slug', 'p'), **kw})

    def test_create_and_listing(self):
        r = self.client.post(self.url('report_schedule_new'), self.form())
        self.assertEqual(r.status_code, 302)
        s = ReportSchedule.objects.get()
        self.assertEqual((s.project, s.frequency, s.weekday, s.hour, s.created_by), (self.p, 'weekly', 1, 7, self.admin))
        html = self.client.get(self.url('reports') + '?tab=recurring').content.decode()
        self.assertIn('Board pack', html)

    def test_invalid_input_creates_nothing(self):
        for bad in (self.form(recipients='nope', delivery='email'), self.form(frequency='daily'), self.form(hour='24'),
                    self.form(day_of_month='29'), self.form(weekday='7'), self.form(name='a\r\nb'),
                    self.form(tag='no-such-tag'), self.form(delivery='email', recipients=''),
                    self.form(hour='x')):
            r = self.client.post(self.url('report_schedule_new'), bad)
            self.assertEqual(r.status_code, 200, bad)
        self.assertEqual(ReportSchedule.objects.count(), 0)

    def test_hostile_name_is_escaped_in_listing(self):
        self.sched(name=X)
        html = self.client.get(self.url('reports') + '?tab=recurring').content.decode()
        self.assertNotIn(X, html)
        self.assertIn(ESCAPED, html)

    def test_cross_project_ids_are_404(self):
        theirs = self.sched(project=self.other)
        run = self.run_for(self.other)
        for name, kw in (('report_schedule_edit', {'schedule_id': theirs.id}), ('report_schedule_toggle', {'schedule_id': theirs.id}),
                         ('report_schedule_delete', {'schedule_id': theirs.id}), ('report_schedule_run', {'schedule_id': theirs.id}),
                         ('report_run_delete', {'run_id': run.id})):
            self.assertEqual(self.client.post(self.url(name, **kw), self.form()).status_code, 404, name)
        self.assertEqual(self.client.get(self.url('report_schedule_edit', schedule_id=theirs.id)).status_code, 404)
        theirs.refresh_from_db()
        self.assertTrue(theirs.enabled)
        self.assertEqual(ReportRun.objects.count(), 1)

    def test_edit_toggle_delete(self):
        s = self.sched()
        self.client.post(self.url('report_schedule_edit', schedule_id=s.id), self.form(name='Renamed'))
        s.refresh_from_db()
        self.assertEqual(s.name, 'Renamed')
        self.client.post(self.url('report_schedule_toggle', schedule_id=s.id))
        s.refresh_from_db()
        self.assertFalse(s.enabled)
        self.client.post(self.url('report_schedule_delete', schedule_id=s.id))
        self.assertEqual(ReportSchedule.objects.count(), 0)

    def test_generate_now_makes_a_run_and_get_is_refused(self):
        self.assertEqual(self.client.get(self.url('report_generate')).status_code, 405)
        r = self.client.post(self.url('report_generate'), {'days': '30', 'tag': ''})
        self.assertEqual(r.status_code, 302)
        run = ReportRun.objects.get()
        self.assertEqual((run.trigger, run.days, run.created_by), ('manual', 30, self.admin))
        html = self.client.get(self.url('reports')).content.decode()
        self.assertIn(reverse('report_download', kwargs={'slug': 'p', 'run_id': run.id}), html)

    def test_auditor_may_read_but_not_manage(self):
        self.client.force_login(self.auditor)
        self.assertEqual(self.client.get(self.url('reports')).status_code, 200)
        self.assertEqual(self.client.get(self.url('executive_summary')).status_code, 200)
        self.client.post(self.url('report_schedule_new'), self.form())
        self.assertEqual(ReportSchedule.objects.count(), 0)

    def test_page_shows_switch_off_banner(self):
        with override_settings(REPORTS_ENABLED=False):
            html = self.client.get(self.url('reports')).content.decode()
        self.assertIn('LIMES_REPORTS_ENABLED', html)


class TaskTest(ReportBase):
    def test_task_is_registered_and_respects_switch(self):
        from reporting import tasks
        self.sched()
        with override_settings(REPORTS_ENABLED=False):
            self.assertEqual(tasks.generate_due_reports(), {'generated': 0})
