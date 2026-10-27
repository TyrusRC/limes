"""Alert rules and the per-project integration settings they send through. Logic: limes.alerts.rules."""
from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone

from dashboard.models import Project

CHANNELS = ('in_app', 'email', 'webhook', 'slack', 'jira')


class AlertRule(models.Model):
    """Send matching change events to some channels. Only an enabled rule matters; a project with no rules keeps
    the default delivery alone."""
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name='alert_rules')
    name = models.CharField(max_length=100)
    enabled = models.BooleanField(default=True)
    kinds = models.JSONField(default=list)  # subset of limes.alerts.events.KINDS
    min_severity = models.IntegerField(null=True, blank=True)  # 1-4; applies only to events that carry a severity
    tags = models.JSONField(default=list)  # any-of asset tag names; empty = no tag condition
    score_drop_points = models.IntegerField(null=True, blank=True)  # score events: fell by this many points ...
    score_window_days = models.IntegerField(null=True, blank=True)  # ... within this many days
    channels = models.JSONField(default=list)  # subset of CHANNELS
    email_to = models.JSONField(default=list)  # recipients of the email channel
    created_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name='+')
    created_at = models.DateTimeField(default=timezone.now)
    last_sent = models.DateTimeField(null=True, blank=True)
    last_error = models.CharField(max_length=300, blank=True, default='')
    last_error_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = ('project', 'name')


class AlertIntegration(models.Model):
    """One row per project. Every *_enc column is Fernet text (limes.identity.encrypt); the API never returns it."""
    project = models.OneToOneField(Project, on_delete=models.CASCADE, related_name='alert_integration')
    webhook_url_enc = models.TextField(blank=True, default='')
    webhook_secret_enc = models.TextField(blank=True, default='')
    slack_url_enc = models.TextField(blank=True, default='')
    jira_base_url = models.CharField(max_length=300, blank=True, default='')
    jira_email = models.CharField(max_length=200, blank=True, default='')
    jira_token_enc = models.TextField(blank=True, default='')
    jira_project_key = models.CharField(max_length=20, blank=True, default='')
    jira_issue_type = models.CharField(max_length=60, blank=True, default='')
    jira_labels = models.JSONField(default=list)
