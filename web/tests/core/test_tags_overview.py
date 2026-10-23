from django.core.cache import cache
from django.db import connection
from django.test.utils import CaptureQueriesContext

from startScan.models import Asset, Tag
from tests.core import test_overview_page as base

X = base.X
ESCAPED = base.ESCAPED


class TagsCardTest(base.OverviewPageBase):
    def tagged(self, name, n=1, project=None):
        tag, _ = Tag.objects.get_or_create(project=project or self.p, name=name)
        for i in range(n):
            a = self.asset(f'{abs(hash(name)) % 10 ** 6}-{i}.x.com', project=project)
            a.tags.add(tag)
        return tag

    def card(self):
        return base.section(self.page('p'), 'dash_tags')

    def test_empty_state_points_at_the_assets_page(self):
        html = self.card()
        self.assertIn('<h2', html)
        self.assertIn('No tags yet', html)

    def test_card_lists_scored_and_unassessed_tags_for_this_project_only(self):
        self.scan()
        self.tagged('prod', 2)
        self.tagged('secret-y', 1, project=self.other)
        far = Asset.objects.create(project=self.p, kind='hostname', value='far.net', scope_tier='owned_host')
        far.tags.add(Tag.objects.create(project=self.p, name='unscored'))
        html = self.card()
        self.assertIn('>prod<', html)
        self.assertIn('ov-grade-a', html)  # both prod hosts are clean: 950
        self.assertIn('Not assessed', html)
        self.assertIn(f'href="{self.issues_url()}?tag=prod"', html)
        self.assertNotIn('secret-y', html)

    def test_hostile_tag_name_is_escaped(self):
        self.scan()
        self.tagged(X)
        html = self.page('p')
        self.assertNotIn(X, html)
        self.assertIn(ESCAPED, base.section(html, 'dash_tags'))
        self.assertNotIn('?tag=<', html)

    def test_queries_do_not_grow_with_tags_or_assets(self):
        self.scan()

        def count():
            self.page('p')
            cache.clear()
            with CaptureQueriesContext(connection) as ctx:
                self.assertEqual(self.client.get('/p/dashboard/').status_code, 200)
            return len(ctx)
        self.tagged('one')
        small = count()
        for i in range(10):
            self.tagged(f'many{i}', 4)
        self.assertEqual(count(), small)
