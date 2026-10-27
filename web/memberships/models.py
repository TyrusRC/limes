from django.conf import settings
from django.db import models
from django.utils import timezone

ADMIN, STANDARD, READ_ONLY = 'admin', 'standard', 'read_only'
ROLES = (ADMIN, STANDARD, READ_ONLY)
RANK = {READ_ONLY: 1, STANDARD: 2, ADMIN: 3}


class ProjectMember(models.Model):
    """What a user may do in one project. No row means no access: the project does not exist for that user."""
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='project_memberships')
    project = models.ForeignKey('dashboard.Project', on_delete=models.CASCADE, related_name='members')
    role = models.CharField(max_length=10, choices=[(r, r) for r in ROLES])
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        constraints = [models.UniqueConstraint(fields=['user', 'project'], name='one_membership_per_user_project')]


class AccessAudit(models.Model):
    """Who changed who may do what. Names are copied in so the trail survives deleted users and projects."""
    created_at = models.DateTimeField(default=timezone.now, db_index=True)
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, related_name='+')
    actor_name = models.CharField(max_length=150, blank=True, default='')
    project = models.ForeignKey('dashboard.Project', on_delete=models.SET_NULL, null=True, related_name='+')
    project_slug = models.CharField(max_length=50, blank=True, default='')
    action = models.CharField(max_length=30)
    subject = models.CharField(max_length=150, blank=True, default='')
    detail = models.CharField(max_length=300, blank=True, default='')


class NotificationRead(models.Model):
    """One user having read one notification. Read state belongs to a person, not to the notification."""
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='+')
    notification = models.ForeignKey('dashboard.InAppNotification', on_delete=models.CASCADE, related_name='+')

    class Meta:
        constraints = [models.UniqueConstraint(fields=['user', 'notification'], name='one_read_mark_per_user_notification')]
