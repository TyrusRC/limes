from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone

from dashboard.models import Project
from startScan.models import TrackedIssue

STATUSES = [(s, s) for s in ('active', 'completed', 'archived')]


class RemediationRequest(models.Model):
    """A bundle of issues somebody is asked to fix by a due date (UpGuard-style remediation request)."""
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='remediation_requests')
    title = models.CharField(max_length=200)
    message = models.TextField(blank=True, default='')
    due_date = models.DateField(null=True, blank=True)
    status = models.CharField(max_length=10, choices=STATUSES, default='active')
    created_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='+')
    assignee = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='+')
    external_emails = models.JSONField(default=list, blank=True)  # at most service.MAX_EMAILS, validated
    email_status = models.CharField(max_length=40, blank=True, default='')  # '', sent, failed, 'email not configured'
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)
    completed_at = models.DateTimeField(null=True, blank=True)
    overdue_notified = models.BooleanField(default=False)

    class Meta:
        indexes = [models.Index(fields=['project', 'status'], name='remreq_proj_status_idx')]


class RemediationItem(models.Model):
    request = models.ForeignKey(RemediationRequest, on_delete=models.CASCADE, related_name='items')
    issue = models.ForeignKey(TrackedIssue, on_delete=models.CASCADE, related_name='+')

    class Meta:
        unique_together = ('request', 'issue')


class RemediationMessage(models.Model):
    """Collaboration notes on a request. Plain text, escaped by every template."""
    request = models.ForeignKey(RemediationRequest, on_delete=models.CASCADE, related_name='messages')
    author = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='+')
    text = models.TextField()
    created_at = models.DateTimeField(default=timezone.now)


class RemediationEvent(models.Model):
    """The timeline: what happened to a request and when."""
    request = models.ForeignKey(RemediationRequest, on_delete=models.CASCADE, related_name='events')
    kind = models.CharField(max_length=20)
    text = models.CharField(max_length=300)
    actor = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='+')
    created_at = models.DateTimeField(default=timezone.now)


class Note(models.Model):
    """A collaboration note on a remediation request, a waiver or an issue. Plain text, append-only (no edit; the
    author may delete their own). target_id is checked against the project in remediation.notes, not by a foreign key."""
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='+')
    target_type = models.CharField(max_length=10)  # request | waiver | issue
    target_id = models.BigIntegerField()
    author = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='+')
    body = models.TextField()
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        indexes = [models.Index(fields=['project', 'target_type', 'target_id', 'created_at'], name='note_target_idx')]
