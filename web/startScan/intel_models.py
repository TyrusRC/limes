from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone

from dashboard.models import Project
from startScan.asset_models import Asset

__all__ = ['FeedState', 'CveIntel', 'Lookalike', 'DomainBreach']


class FeedState(models.Model):
    """One row per downloaded third-party feed (limes.feeds.store). `source_date` is the feed's own timestamp."""
    name = models.CharField(max_length=64, unique=True)
    url = models.CharField(max_length=500)
    fetched_at = models.DateTimeField(null=True)
    last_good_at = models.DateTimeField(null=True)
    source_date = models.DateTimeField(null=True)
    etag = models.CharField(max_length=200, blank=True)
    last_modified = models.CharField(max_length=100, blank=True)
    sha256 = models.CharField(max_length=64, blank=True)
    entries = models.IntegerField(default=0)
    status = models.CharField(max_length=16, default='never')  # never|ok|not_modified|error|rejected
    error = models.CharField(max_length=300, blank=True)
    # consecutive 'shrank' rejections of the same copy (store._problem); 3 in a row and the copy is accepted
    shrank_count = models.IntegerField(default=0)
    shrank_sha256 = models.CharField(max_length=64, blank=True)


class CveIntel(models.Model):
    cve = models.CharField(max_length=20, unique=True)
    epss = models.FloatField(null=True)
    percentile = models.FloatField(null=True)
    epss_date = models.DateField(null=True)
    kev = models.BooleanField(default=False)
    kev_added = models.DateField(null=True)
    kev_due = models.DateField(null=True)
    kev_ransomware = models.BooleanField(null=True)
    updated_at = models.DateTimeField(default=timezone.now)


class Lookalike(models.Model):
    """A third-party candidate domain. Never an Asset row: no scan or monitor selector can reach it."""
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    root = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='lookalikes')
    domain = models.CharField(max_length=253)  # ascii / punycode
    unicode = models.CharField(max_length=253)
    fuzzers = models.JSONField(default=list)
    source = models.CharField(max_length=12)  # permutation|ct
    status = models.CharField(max_length=12, default='unchecked')
    registered = models.BooleanField(null=True)
    dns = models.JSONField(default=dict)
    has_mx = models.BooleanField(default=False)
    rdap = models.JSONField(default=dict)
    ct = models.JSONField(default=dict)
    http = models.JSONField(null=True)
    first_seen = models.DateTimeField(default=timezone.now)
    last_checked = models.DateTimeField(null=True)
    next_check = models.DateTimeField(default=timezone.now, db_index=True)
    rdap_checked_at = models.DateTimeField(null=True)
    ct_checked_at = models.DateTimeField(null=True)
    decided_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    decided_at = models.DateTimeField(null=True)
    reported_at = models.DateTimeField(null=True)
    note = models.TextField(blank=True)

    class Meta:
        unique_together = ('project', 'domain')


class DomainBreach(models.Model):
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    root = models.ForeignKey(Asset, on_delete=models.CASCADE)
    breach_name = models.CharField(max_length=100)
    addresses = models.IntegerField()
    breach_date = models.DateField(null=True)
    published = models.DateTimeField(null=True)
    first_seen = models.DateTimeField(default=timezone.now)

    class Meta:
        unique_together = ('root', 'breach_name')
