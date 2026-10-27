from django.urls import reverse

from reporting import sched, summary, validate
from reporting.models import ReportSchedule, ReportTemplate
from tests.core.test_reporting import ESCAPED, X, ReportBase


class TemplateTest(ReportBase):
    def url(self, name, **kw):
        return reverse(name, kwargs={'slug': kw.pop('slug', 'p'), **kw})

    def tpl(self, project=None, **kw):
        kw.setdefault('name', 'T')
        kw.setdefault('sections', ['score'])
        return ReportTemplate.objects.create(project=project or self.p, **kw)

    def page(self, tpl):
        return self.client.get(self.url('executive_summary'), {'template': tpl.id}).content.decode()

    def test_only_picked_sections_render(self):
        self.vuln(self.asset('a.x.com'), 'some-issue', 3)
        html = self.page(self.tpl(sections=['risks', 'waivers']))
        self.assertIn('id="rpt_risks"', html)
        self.assertIn('id="rpt_waivers"', html)
        for gone in ('rpt_score', 'rpt_categories', 'rpt_changed', 'rpt_progress', 'rpt_tags', 'rpt_remreq'):
            self.assertNotIn(f'id="{gone}"', html)
        self.assertIn('id="rpt_score"', self.client.get(self.url('executive_summary')).content.decode())  # plain page unchanged

    def test_commentary_is_escaped_and_capped(self):
        html = self.page(self.tpl(commentary=X))
        self.assertNotIn(X, html)
        self.assertIn(ESCAPED, html)
        with self.assertRaises(validate.ReportError):
            validate.commentary('x' * 11, 10)
        self.assertEqual(validate.commentary('a\x00b\r\nc', 10), 'a b\nc')
        r = self.client.post(self.url('report_template_new'), {'name': 'big', 'layout': 'full', 'sections': ['score'], 'commentary': 'x' * 2001})
        self.assertEqual(r.status_code, 200)
        self.assertFalse(ReportTemplate.objects.filter(name='big').exists())

    def test_board_layout_is_one_page_with_top_five(self):
        a = self.asset('a.x.com')
        self.vulns([(a, f'issue-{i}', 3) for i in range(7)])
        html = self.page(self.tpl(layout='board', commentary='Approve budget'))
        self.assertIn('What we need decided', html)
        self.assertIn('Approve budget', html)
        self.assertEqual(html.count('issue-'), 5)
        self.assertNotIn('rpt_categories', html)

    def test_create_via_form_and_project_scoping(self):
        r = self.client.post(self.url('report_template_new'), {'name': 'Mine', 'layout': 'full', 'sections': ['score', 'bogus'], 'commentary': 'hi'})
        self.assertEqual(r.status_code, 302)
        t = ReportTemplate.objects.get()
        self.assertEqual((t.project, t.sections), (self.p, ['score']))
        theirs = self.tpl(project=self.other, name='Theirs')
        self.assertEqual(self.client.get(self.url('executive_summary'), {'template': theirs.id}).status_code, 404)
        self.assertEqual(self.client.get(self.url('report_template_edit', template_id=theirs.id)).status_code, 404)
        self.assertEqual(self.client.post(self.url('report_template_delete', template_id=theirs.id)).status_code, 404)
        self.assertNotIn('Theirs', self.client.get(self.url('reports') + '?tab=templates').content.decode())
        with self.assertRaises(ValueError):
            summary.build(self.p, template=theirs)

    def test_schedule_rejects_other_projects_template(self):
        theirs = self.tpl(project=self.other, name='Theirs')
        form = {'name': 'S', 'frequency': 'weekly', 'weekday': '1', 'day_of_month': '1', 'hour': '7', 'delivery': 'platform',
                'enabled': 'on', 'template': theirs.id}
        r = self.client.post(self.url('report_schedule_new'), form)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(ReportSchedule.objects.count(), 0)
        mine = self.tpl(name='Mine')
        self.assertEqual(self.client.post(self.url('report_schedule_new'), {**form, 'template': mine.id}).status_code, 302)
        self.assertEqual(ReportSchedule.objects.get().template, mine)

    def test_scheduled_run_uses_template_and_tag(self):
        a = self.asset('a.x.com')
        self.tag(a, 'prod')
        self.vuln(a, 'some-issue', 3)
        s = self.sched(template=self.tpl(sections=['risks'], commentary='Note'), tag='prod')
        run = sched.generate(self.p, s.name, schedule=s, trigger='schedule', period_key='k')
        from reporting import store
        html = open(store.path(run)).read()
        self.assertIn('id="rpt_risks"', html)
        self.assertNotIn('id="rpt_score"', html)
        self.assertIn('Note', html)
        self.assertEqual(run.tag, 'prod')
