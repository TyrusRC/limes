from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone

from dashboard.models import Project
from limes.definitions import CELERY_TASK_STATUSES
from startScan.models import IpAddress, Technology

ASSET_KINDS = [('root_domain', 'root_domain'), ('hostname', 'hostname'), ('ip', 'ip'), ('cidr', 'cidr')]
SCOPE_TIERS = [('owned_root', 'owned_root'), ('owned_host', 'owned_host'),
               ('co_brand', 'co_brand'), ('candidate', 'candidate'), ('rejected', 'rejected'),
               ('dependency', 'dependency')]  # infrastructure we rely on, never scanned by IP
ASSET_STATES = [('active', 'active'), ('missing', 'missing'), ('stale', 'stale'), ('retired', 'retired')]
MISSING_THRESHOLD = 3
SCAN_MODES = [(m, m) for m in ('asm', 'scanner', 'full')]
SCAN_STAGES = [(s, s) for s in ('discovery', 'resolve', 'ports', 'probe', 'crawl', 'dast', 'code')]


__all__ = ['Tag', 'Asset', 'ScanRun', 'ScanJob']


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
    missed_count = models.IntegerField(default=0)

    sources = models.JSONField(default=list, blank=True)
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
    cadence_tier = models.CharField(max_length=20, default='standard')
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
            if self.state == 'missing':
                self.state = 'active'
        else:
            self.missed_count += 1
            if self.missed_count >= MISSING_THRESHOLD and self.state == 'active':
                self.state = 'missing'
        self.save(update_fields=['missed_count', 'last_seen', 'state'])


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
