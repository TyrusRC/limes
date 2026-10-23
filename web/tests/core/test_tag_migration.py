from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase

BEFORE = [('startScan', '0031_drop_gpt_report')]
AFTER = [('startScan', '0034_tag_project_required')]


class TagMigrationTest(TransactionTestCase):
    def migrate(self, targets):
        ex = MigrationExecutor(connection)
        ex.migrate(targets)
        return MigrationExecutor(connection).loader.project_state(targets).apps

    def tearDown(self):
        MigrationExecutor(connection).migrate(MigrationExecutor(connection).loader.graph.leaf_nodes())

    def test_global_tags_become_per_project_tags(self):
        old = self.migrate(BEFORE)
        Project, Asset, Tag = (old.get_model(a, m) for a, m in (('dashboard', 'Project'), ('startScan', 'Asset'), ('startScan', 'Tag')))
        p1 = Project.objects.create(name='p1', slug='p1', insert_date='2026-01-01T00:00:00Z')
        p2 = Project.objects.create(name='p2', slug='p2', insert_date='2026-01-01T00:00:00Z')
        a1 = Asset.objects.create(project=p1, kind='hostname', value='a.x.com')
        a2 = Asset.objects.create(project=p2, kind='hostname', value='a.y.com')
        a3 = Asset.objects.create(project=p2, kind='hostname', value='b.y.com')
        prod, odd, unused = Tag.objects.create(name='prod'), Tag.objects.create(name='Odd Name!'), Tag.objects.create(name='unused')
        a1.tags.add(prod, odd)
        a2.tags.add(prod)
        a3.tags.add(prod)
        new = self.migrate(AFTER)
        Asset, Tag = new.get_model('startScan', 'Asset'), new.get_model('startScan', 'Tag')
        self.assertEqual(sorted(Tag.objects.values_list('project__slug', 'name')),
                         [('p1', 'odd-name'), ('p1', 'prod'), ('p2', 'prod')])  # unused is gone, names normalised
        tags = lambda v: sorted(Asset.objects.get(value=v).tags.values_list('project__slug', 'name'))
        self.assertEqual(tags('a.x.com'), [('p1', 'odd-name'), ('p1', 'prod')])
        self.assertEqual(tags('a.y.com'), [('p2', 'prod')])  # never p1's row
        self.assertEqual(tags('b.y.com'), [('p2', 'prod')])
        self.assertEqual(Tag.objects.get(project__slug='p2', name='prod').assets.count(), 2)

    def test_names_with_nothing_usable_keep_their_assignment(self):
        old = self.migrate(BEFORE)
        Project, Asset, Tag = (old.get_model(a, m) for a, m in (('dashboard', 'Project'), ('startScan', 'Asset'), ('startScan', 'Tag')))
        p = Project.objects.create(name='p1', slug='p1', insert_date='2026-01-01T00:00:00Z')
        a = Asset.objects.create(project=p, kind='hostname', value='a.x.com')
        olds = [Tag.objects.create(name=n) for n in ('!!!', '___', '\u751f\u4ea7', 'ok')]
        a.tags.add(*olds)
        new = self.migrate(AFTER)
        names = sorted(new.get_model('startScan', 'Asset').objects.get(value='a.x.com').tags.values_list('name', flat=True))
        self.assertEqual(names, sorted([f'tag-{olds[0].pk}', f'tag-{olds[1].pk}', f'tag-{olds[2].pk}', 'ok']))
