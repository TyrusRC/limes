from datetime import timedelta

from django.contrib.auth.models import User
from django.utils import timezone
from rolepermissions.roles import assign_role

from dashboard.models import Project
from limes import scoring, waivers
from startScan.models import IssueWaiver, TrackedIssue
from tests.core.test_scoring import Base


class Scope(Base):
    def setUp(self):
        super().setUp()
        self.me = User.objects.create_user('me')
        self.boss = User.objects.create_user('boss')
        assign_role(self.me, 'sys_admin')
        assign_role(self.boss, 'sys_admin')
        self.outsider = User.objects.create_user('outsider')  # no role: not a member
        self.s = self.scan()
        self.a = self.host('a.x.com')
        self.vuln(self.s, self.a, 3)
        self.issue = TrackedIssue.objects.create(project=self.p, asset=self.a, key='t1', source='finding', severity=3)

    def score(self):
        s = scoring.project_score(self.p)
        return s['score'], s['raw_score']


class PendingApprovalTest(Scope):
    def test_pending_waiver_does_not_reduce_the_score_until_approved(self):
        w = waivers.create_waiver(self.issue, 'accepted_risk', 'r', self.me, approver=self.boss)
        self.assertTrue(w.approval_pending)
        self.assertEqual(self.score(), (799, 799))
        self.assertIsNone(waivers.active_waiver(self.issue))
        waivers.decide_waiver(self.p, w.id, self.boss, True)
        self.assertEqual(self.score(), (950, 799))

    def test_requester_cannot_approve_their_own_waiver(self):
        with self.assertRaises(waivers.WaiverError):
            waivers.create_waiver(self.issue, 'accepted_risk', 'r', self.me, approver=self.me)
        # a waiver whose approver is also its author (written around create_waiver) still cannot be decided
        w = waivers.create_waiver(self.issue, 'accepted_risk', 'r', self.me, approver=self.boss)
        IssueWaiver.objects.filter(pk=w.pk).update(created_by=self.boss)
        with self.assertRaises(waivers.WaiverError):
            waivers.decide_waiver(self.p, w.id, self.boss, True)
        self.assertEqual(self.score(), (799, 799))

    def test_only_the_named_approver_decides(self):
        w = waivers.create_waiver(self.issue, 'accepted_risk', 'r', self.me, approver=self.boss)
        for who in (self.me, self.outsider):
            with self.assertRaises(waivers.WaiverError):
                waivers.decide_waiver(self.p, w.id, who, True)
        self.assertEqual(self.score(), (799, 799))

    def test_approver_must_be_a_member(self):
        with self.assertRaises(waivers.WaiverError):
            waivers.create_waiver(self.issue, 'accepted_risk', 'r', self.me, approver=self.outsider)
        self.boss.is_active = False
        self.boss.save()
        with self.assertRaises(waivers.WaiverError):
            waivers.create_waiver(self.issue, 'accepted_risk', 'r', self.me, approver=self.boss)
        self.assertEqual(IssueWaiver.objects.count(), 0)

    def test_rejected_waiver_never_counts_and_cannot_be_decided_twice(self):
        w = waivers.create_waiver(self.issue, 'accepted_risk', 'r', self.me, approver=self.boss)
        waivers.decide_waiver(self.p, w.id, self.boss, False)
        self.assertEqual(self.score(), (799, 799))
        with self.assertRaises(waivers.WaiverError):
            waivers.decide_waiver(self.p, w.id, self.boss, True)

    def test_pending_replacement_keeps_the_old_waiver_until_approved(self):
        old = waivers.create_waiver(self.issue, 'accepted_risk', 'old', self.me)
        new = waivers.create_waiver(self.issue, 'false_positive', 'new', self.me, approver=self.boss)
        self.assertEqual(waivers.active_waiver(self.issue), old)
        waivers.decide_waiver(self.p, new.id, self.boss, True)
        old.refresh_from_db()
        self.assertIsNotNone(old.revoked_at)
        self.assertEqual(waivers.active_waiver(self.issue), new)

    def test_other_project_waiver_id_is_not_found(self):
        q = Project.objects.create(name='q', slug='q', insert_date=timezone.now())
        w = waivers.create_waiver(self.issue, 'accepted_risk', 'r', self.me, approver=self.boss)
        with self.assertRaises(LookupError):
            waivers.decide_waiver(q, w.id, self.boss, True)
        with self.assertRaises(LookupError):
            waivers.revoke_waiver_id(q, w.id, self.me)


class ProjectWideTest(Scope):
    def test_applies_to_an_asset_created_later_and_revoking_restores(self):
        w = waivers.create_waiver(self.issue, 'accepted_risk', 'r', self.me, scope='all')
        self.assertIsNone(w.issue_id)
        self.assertEqual(self.score(), (950, 799))
        b = self.host('b.x.com')  # created after the waiver, no TrackedIssue row yet
        self.vuln(self.s, b, 3)
        self.assertEqual(self.score(), (950, 799))
        self.assertTrue(scoring.asset_breakdown(b)['penalties'][0]['waived'])
        self.assertTrue(waivers.revoke_waiver_id(self.p, w.id, self.me))
        self.assertEqual(self.score(), (799, 799))

    def test_does_not_leak_to_other_keys_or_projects(self):
        waivers.create_waiver(self.issue, 'accepted_risk', 'r', self.me, scope='all')
        c = self.host('c.x.com')
        self.vuln(self.s, c, 4, template='other')
        self.assertEqual(self.score()[0], 599)
        q = Project.objects.create(name='q', slug='q', insert_date=timezone.now())
        self.assertEqual(scoring.waived_keys(q).wide, frozenset())

    def test_expired_project_wide_waiver_counts_again(self):
        waivers.create_waiver(self.issue, 'accepted_risk', 'r', self.me, scope='all', now=self.now - timedelta(days=100),
                              expires_at=self.now - timedelta(days=100) + timedelta(days=90))
        self.assertEqual(self.score(), (799, 799))

    def test_issue_listing_shows_it_for_every_asset(self):
        waivers.create_waiver(self.issue, 'accepted_risk', 'r', self.me, scope='all')
        later = TrackedIssue.objects.create(project=self.p, asset=self.host('b.x.com'), key='t1', source='finding', severity=3)
        qs = TrackedIssue.objects.filter(project=self.p, key='t1')
        self.assertEqual(qs.filter(IssueWaiver.waived_exists(timezone.now())).count(), 2)
        self.assertEqual(scoring.category_issue_counts(self.p)['vulnerabilities'], {'open': 2, 'waived': 2})
        self.assertIsNotNone(later.id)

    def test_pending_project_wide_waiver_is_not_in_force(self):
        waivers.create_waiver(self.issue, 'accepted_risk', 'r', self.me, scope='all', approver=self.boss)
        self.assertEqual(self.score(), (799, 799))
        self.assertEqual(scoring.waived_keys(self.p).wide, frozenset())

    def test_validation(self):
        for kw in ({'scope': 'galaxy'}, {'remind_days': 0}, {'remind_days': 91}, {'remind_days': True}):
            with self.subTest(kw=kw), self.assertRaises(waivers.WaiverError):
                waivers.create_waiver(self.issue, 'accepted_risk', 'r', self.me, **kw)


class ExistingWaiverRegressionTest(Scope):
    """Issue-level waivers keep their old meaning: out of the headline, in raw_score, counted in waived_count."""

    def test_issue_waiver_semantics_unchanged(self):
        waivers.create_waiver(self.issue, 'accepted_risk', 'r', self.me)
        s = scoring.project_score(self.p)
        self.assertEqual((s['score'], s['raw_score'], s['waived_count'], s['version']), (950, 799, 1, 'limes-score-v3'))
        self.assertEqual(scoring.category_issue_counts(self.p)['vulnerabilities'], {'open': 1, 'waived': 1})

    def test_legacy_row_without_the_new_fields_still_counts(self):
        IssueWaiver.objects.create(issue=self.issue, kind='accepted_risk', reason='old',
                                   expires_at=timezone.now() + timedelta(days=3))
        self.assertEqual(self.score(), (950, 799))
