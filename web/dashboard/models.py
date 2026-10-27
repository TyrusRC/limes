from django.conf import settings
from django.db import models
from django.utils import timezone
from limes.definitions import *


class SearchHistory(models.Model):
	query = models.CharField(max_length=1000)

	def __str__(self):
		return self.query


class Project(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=500)
	slug = models.SlugField(unique=True)
	insert_date = models.DateTimeField()
	brand_keywords = models.JSONField(default=list, blank=True)

	def __str__(self):
		return self.slug


class InAppNotification(models.Model):
	project = models.ForeignKey(Project, on_delete=models.CASCADE, null=True, blank=True)
	notification_type = models.CharField(max_length=10, choices=NOTIFICATION_TYPES, default='system')
	status = models.CharField(max_length=10, choices=NOTIFICATION_STATUS_TYPES, default='info')
	title = models.CharField(max_length=255)
	description = models.TextField()
	icon = models.CharField(max_length=50) # mdi icon class name
	is_read = models.BooleanField(default=False)
	created_at = models.DateTimeField(auto_now_add=True)
	redirect_link = models.URLField(max_length=255, blank=True, null=True)
	open_in_new_tab = models.BooleanField(default=False)

	class Meta:
		ordering = ['-created_at']

	def __str__(self):
		if self.notification_type == 'system':
			return f"System wide notif: {self.title}"
		else:
			return f"Project wide notif: {self.project.name}: {self.title}"
		
	@property
	def is_system_wide(self):
		# property to determine if the notification is system wide or project specific
		return self.notification_type == 'system'


class ApiToken(models.Model):
	"""A personal API token for the MCP server. Only the SHA-256 of the full token and its public id are stored."""
	user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='api_tokens')
	name = models.CharField(max_length=100)
	token_id = models.CharField(max_length=8, unique=True)
	token_hash = models.CharField(max_length=64)
	scope = models.CharField(max_length=10, choices=[('read', 'read'), ('read_write', 'read_write')])
	created_at = models.DateTimeField(default=timezone.now)
	expires_at = models.DateTimeField()
	last_used_at = models.DateTimeField(null=True, blank=True)
	revoked_at = models.DateTimeField(null=True, blank=True)

	def usable(self, now):
		return self.revoked_at is None and self.expires_at > now

	def __str__(self):
		return f'lmk_{self.token_id}_...'

	def __repr__(self):
		return f'<ApiToken {self.token_id}>'


class McpCallLog(models.Model):
	token = models.ForeignKey(ApiToken, on_delete=models.SET_NULL, null=True)
	token_public_id = models.CharField(max_length=8)
	user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
	tool = models.CharField(max_length=64)
	project = models.CharField(max_length=50, blank=True, default='')
	arguments = models.TextField(blank=True, default='')
	outcome = models.CharField(max_length=20)
	write = models.BooleanField(default=False)
	duration_ms = models.IntegerField()
	created_at = models.DateTimeField(default=timezone.now, db_index=True)
