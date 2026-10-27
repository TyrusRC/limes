from django.test import SimpleTestCase

from limes.issue_groups import group


def row(i, asset, key='web.hsts_missing', sev=2, first='2026-01-05T00:00:00Z', waiver=None, expired=None, prov=False, kev=False, epss=None):
    return {'id': i, 'asset': asset, 'asset_kind': 'hostname', 'key': key, 'source': 'check', 'title': key, 'category': 'web',
            'category_label': 'Website', 'severity': sev, 'provisional': prov, 'first_seen': first, 'waiver': waiver,
            'expired_waiver': expired, 'note_count': 1, 'kev': kev, 'epss': epss}


class GroupTest(SimpleTestCase):
    def test_one_group_per_issue_with_its_assets(self):
        (g,) = group([row(1, 'a'), row(2, 'b', first='2026-01-02T00:00:00Z'), row(3, 'c', key='other')][:2])
        self.assertEqual((g['count'], g['first_seen'], g['id'], g['note_count']), (2, '2026-01-02T00:00:00Z', 2, 2))
        self.assertEqual([a['asset'] for a in g['assets']], ['b', 'a'])  # oldest first
        self.assertEqual(g['unwaived_ids'], [2, 1])

    def test_worst_first_and_informational_last(self):
        gs = group([row(1, 'a', key='low', sev=1), row(2, 'a', key='crit', sev=4), row(3, 'a', key='prov', sev=4, prov=True),
                    row(4, 'a', key='high', sev=3)])
        self.assertEqual([g['key'] for g in gs], ['crit', 'high', 'low', 'prov'])
        self.assertTrue(gs[-1]['provisional'])

    def test_more_assets_sorts_first_within_a_severity(self):
        gs = group([row(1, 'a', key='one'), row(2, 'a', key='two'), row(3, 'b', key='two')])
        self.assertEqual([g['key'] for g in gs], ['two', 'one'])

    def test_status(self):
        w = {'kind': 'accepted_risk'}
        self.assertEqual(group([row(1, 'a', waiver=w), row(2, 'b', waiver=w)])[0]['status'], 'waived')
        self.assertEqual(group([row(1, 'a', waiver=w), row(2, 'b')])[0]['status'], 'partial')
        self.assertEqual(group([row(1, 'a', expired=w)])[0]['status'], 'expired')
        self.assertEqual(group([row(1, 'a')])[0]['status'], 'open')
        self.assertEqual(group([row(1, 'a', waiver=w), row(2, 'b')])[0]['unwaived_ids'], [2])

    def test_kev_epss_and_asset_cap(self):
        g = group([row(i, f'h{i}', kev=i == 3, epss=i / 10) for i in range(1, 130)])[0]
        self.assertEqual((g['count'], len(g['assets']), g['kev'], g['epss']), (129, 100, True, 12.9))
        self.assertEqual(len(g['unwaived_ids']), 129)

    def test_empty(self):
        self.assertEqual(group([]), [])
