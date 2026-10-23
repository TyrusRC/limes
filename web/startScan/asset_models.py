from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone

from dashboard.models import Project
from limes.definitions import CELERY_TASK_STATUSES
from startScan.models import IpAddress, Technology

ASSET_KINDS = [('root_domain', 'root_domain'), ('hostname', 'hostname'), ('ip', 'ip'), ('cidr', 'cidr'),
               ('asn', 'asn')]
SCOPE_TIERS = [('owned_root', 'owned_root'), ('owned_host', 'owned_host'),
               ('co_brand', 'co_brand'), ('candidate', 'candidate'), ('rejected', 'rejected'),
               ('dependency', 'dependency')]  # infrastructure we rely on, never scanned by IP
ASSET_STATES = [('active', 'active'), ('missing', 'missing'), ('stale', 'stale'), ('retired', 'retired')]
MISSING_THRESHOLD = 3
CADENCE_TIERS = [(t, t) for t in ('crown_jewel', 'standard', 'inactive', 'off')]  # intervals: limes.continuous
SCAN_MODES = [(m, m) for m in ('asm', 'scanner', 'full')]
SCAN_STAGES = [(s, s) for s in ('discovery', 'resolve', 'ports', 'probe', 'crawl', 'dast', 'code')]


__all__ = ['Tag', 'Asset', 'AssetFact', 'ScanRun', 'ScanJob', 'ScoreSnapshot', 'RiskCheck',
           'TrackedIssue', 'ChangeEvent', 'IssueSyncState', 'IssueWaiver', 'IssueNote', 'CertSighting']


class Tag(models.Model):
    name = models.CharField(max_length=100, unique=True)

    def __str__(self):
        return self.name


class Asset(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    kind = models.CharField(max_length=20, choices=ASSET_KINDS)
    value = models.CharField(max_length=1000)
    parent = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, blank=True, related_name='children')

    scope_tier = models.CharField(max_length=20, choices=SCOPE_TIERS, default='candidate')
    active_authorized = models.BooleanField(default=False)
    state = models.CharField(max_length=20, choices=ASSET_STATES, default='active')
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    last_resolved_at = models.DateTimeField(null=True, blank=True)
    missed_count = models.IntegerField(default=0)

    sources = models.JSONField(default=list, blank=True)
    enrichment = models.JSONField(default=dict, blank=True)
    confidence = models.FloatField(null=True, blank=True)
    confidence_detail = models.JSONField(null=True, blank=True)
    added_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    decision_reason = models.TextField(blank=True, default='')

    # current observed state (hostname kind; nullable)
    http_status = models.IntegerField(null=True, blank=True)
    page_title = models.CharField(max_length=1000, null=True, blank=True)
    webserver = models.CharField(max_length=1000, null=True, blank=True)
    content_type = models.CharField(max_length=100, null=True, blank=True)
    content_length = models.IntegerField(null=True, blank=True)
    response_time = models.FloatField(null=True, blank=True)
    cname = models.CharField(max_length=5000, null=True, blank=True)
    is_cdn = models.BooleanField(default=False)
    cdn_name = models.CharField(max_length=200, null=True, blank=True)
    screenshot_path = models.CharField(max_length=1000, null=True, blank=True)
    technologies = models.ManyToManyField(Technology, blank=True, related_name='assets')
    ip_addresses = models.ManyToManyField(IpAddress, blank=True, related_name='assets')

    tags = models.ManyToManyField(Tag, blank=True, related_name='assets')
    cadence_tier = models.CharField(max_length=20, choices=CADENCE_TIERS, default='standard')
    request_headers = models.JSONField(null=True, blank=True)

    class Meta:
        unique_together = ('project', 'kind', 'value')
        indexes = [
            models.Index(fields=['project', 'kind'], name='asset_proj_kind_idx'),
            models.Index(fields=['project', 'scope_tier'], name='asset_proj_scope_idx'),
            models.Index(fields=['project', 'state'], name='asset_proj_state_idx'),
        ]

    def __str__(self):
        return f'{self.kind}:{self.value}'

    @property
    def is_active_scan_allowed(self):
        if self.scope_tier in ('owned_root', 'owned_host'):
            return True
        if self.scope_tier == 'co_brand' and self.active_authorized:
            return True
        return False

    def mark_missing_or_seen(self, seen):
        if seen:
            self.missed_count = 0
            self.last_seen = timezone.now()
            if self.state in ('missing', 'stale', 'retired'):
                self.state = 'active'
        else:
            self.missed_count += 1
            if self.missed_count >= MISSING_THRESHOLD and self.state == 'active':
                self.state = 'missing'
        self.save(update_fields=['missed_count', 'last_seen', 'state'])


class AssetFact(models.Model):
    """Typed ownership evidence attached to an asset (A3c attribution graph)."""
    KINDS = [(k, k) for k in ('cert', 'ip', 'ns', 'mx', 'delegation')]

    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='facts')
    kind = models.CharField(max_length=10, choices=KINDS)
    value = models.CharField(max_length=500)
    source = models.CharField(max_length=50)
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)

    class Meta:
        unique_together = ('asset', 'kind', 'value')
        indexes = [models.Index(fields=['kind', 'value'], name='assetfact_kind_value_idx')]


class ScanRun(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    root_asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='scan_runs')
    profile = models.CharField(max_length=20, default='normal')
    mode = models.CharField(max_length=10, choices=SCAN_MODES, default='full')
    status = models.IntegerField(choices=CELERY_TASK_STATUSES, default=-1)
    initiated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    results_dir = models.CharField(max_length=200, blank=True, default='')
    start_scan_date = models.DateTimeField()
    stop_scan_date = models.DateTimeField(null=True, blank=True)
    error_message = models.CharField(max_length=300, null=True, blank=True)


class ScanJob(models.Model):
    run = models.ForeignKey(ScanRun, on_delete=models.CASCADE, related_name='jobs')
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='scan_jobs')
    stage = models.CharField(max_length=20, choices=SCAN_STAGES)
    status = models.IntegerField(choices=CELERY_TASK_STATUSES, default=-1)
    started = models.DateTimeField(null=True, blank=True)
    finished = models.DateTimeField(null=True, blank=True)
    celery_id = models.CharField(max_length=100, null=True, blank=True)
    output_path = models.CharField(max_length=300, null=True, blank=True)
    error_message = models.CharField(max_length=300, null=True, blank=True)

    class Meta:
        indexes = [models.Index(fields=['run', 'stage'], name='scanjob_run_stage_idx'),
                   models.Index(fields=['asset', 'stage'], name='scanjob_asset_stage_idx')]


class ScoreSnapshot(models.Model):
    """Daily project risk score (A4, limes.scoring), kept with the model version that produced it."""
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='score_snapshots')
    date = models.DateField()
    version = models.CharField(max_length=30)
    score = models.IntegerField(null=True, blank=True)
    grade = models.CharField(max_length=3)
    coverage = models.FloatField(null=True, blank=True)
    asset_count = models.IntegerField(default=0)
    top_penalties = models.JSONField(default=list)
    raw_score = models.IntegerField(null=True, blank=True)  # score ignoring waivers
    categories = models.JSONField(null=True, blank=True)  # {category: adjusted score | None}; null on older rows

    class Meta:
        unique_together = ('project', 'date')


class RiskCheck(models.Model):
    """Latest result of one configuration check on one asset (limes.checks)."""
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='risk_checks')
    check_id = models.CharField(max_length=60)
    status = models.CharField(max_length=16)
    severity = models.IntegerField()
    evidence = models.JSONField(default=dict)
    first_seen = models.DateTimeField(default=timezone.now)
    last_checked = models.DateTimeField(default=timezone.now)

    class Meta:
        unique_together = ('asset', 'check_id')


class TrackedIssue(models.Model):
    """One issue (finding template or check id) on one asset, kept across scans so a change is seen once."""
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='tracked_issues')
    key = models.CharField(max_length=255)
    source = models.CharField(max_length=10)  # 'check' or 'finding'
    severity = models.IntegerField()
    status = models.CharField(max_length=8, default='open')  # open | fixed
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    fixed_at = models.DateTimeField(null=True, blank=True)
    reopened = models.IntegerField(default=0)
    reopened_at = models.DateTimeField(null=True, blank=True)  # when it last came back; first_seen is the first detection

    class Meta:
        unique_together = ('asset', 'key')


class IssueWaiver(models.Model):
    """A decision to stop counting an issue: accepted_risk | false_positive. Active = not revoked and not past expires_at."""
    issue = models.ForeignKey(TrackedIssue, on_delete=models.CASCADE, related_name='waivers')
    kind = models.CharField(max_length=16)
    reason = models.TextField()
    created_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='+')
    created_at = models.DateTimeField(default=timezone.now)
    expires_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='+')
    expiry_notified = models.BooleanField(default=False)

    @staticmethod
    def active_q(now):
        """The one definition of active: not revoked and (open-ended or expires_at > now)."""
        return models.Q(revoked_at__isnull=True) & (models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=now))


class IssueNote(models.Model):
    issue = models.ForeignKey(TrackedIssue, on_delete=models.CASCADE, related_name='notes')
    author = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='+')
    text = models.TextField()
    created_at = models.DateTimeField(default=timezone.now)


class ChangeEvent(models.Model):
    """A change worth telling someone about. Delivery state lives in notified_at / digested_at."""
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='change_events')
    kind = models.CharField(max_length=32)
    severity = models.IntegerField(null=True, blank=True)
    asset = models.ForeignKey(Asset, null=True, blank=True, on_delete=models.SET_NULL)
    title = models.CharField(max_length=300)
    detail = models.JSONField(default=dict)
    immediate = models.BooleanField(default=False)
    created_at = models.DateTimeField(default=timezone.now)
    notified_at = models.DateTimeField(null=True, blank=True)
    digested_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [models.Index(fields=['project', 'created_at'])]


class CertSighting(models.Model):
    """One certificate seen in the CT log for a project's names, kept once per (project, TBS hash)."""
    SOURCES = [(s, s) for s in ('certspotter', 'certspotter_api', 'crtsh')]

    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    asset = models.ForeignKey(Asset, null=True, blank=True, on_delete=models.SET_NULL)
    tbs_sha256 = models.CharField(max_length=64)
    cert_sha256 = models.CharField(max_length=64, null=True, blank=True)
    names = models.JSONField(default=list)  # at most 100; the rest are only counted
    other_names = models.IntegerField(default=0)
    wildcard = models.BooleanField(default=False)
    issuer = models.CharField(max_length=500, blank=True)
    not_before = models.DateTimeField(null=True, blank=True)
    not_after = models.DateTimeField(null=True, blank=True)
    log_uri = models.CharField(max_length=500, blank=True)
    entry_index = models.BigIntegerField(null=True, blank=True)
    source = models.CharField(max_length=20, choices=SOURCES)
    first_seen_at = models.DateTimeField(default=timezone.now)
    watch_seen_at = models.DateTimeField(null=True, blank=True)  # set when the watcher delivers this tbs
    api_while_watch_ok = models.BooleanField(default=False)

    class Meta:
        constraints = [models.UniqueConstraint(fields=['project', 'tbs_sha256'], name='certsighting_proj_tbs')]
        indexes = [models.Index(fields=['project', 'first_seen_at'])]


class IssueSyncState(models.Model):
    """Exists once a project's issues have been synced, whether or not it had any (first sync is silent)."""
    project = models.OneToOneField(Project, on_delete=models.CASCADE, related_name='issue_sync')
    first_synced_at = models.DateTimeField(default=timezone.now)
    roots = models.JSONField(default=list)  # root values already synced ('#ips' for IP assets); a new one is silent
