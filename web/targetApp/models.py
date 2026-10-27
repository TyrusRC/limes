from django.apps import apps
from django.db import models
from dashboard.models import Project


class Domain(models.Model):
	id = models.AutoField(primary_key=True)
	name = models.CharField(max_length=300, unique=True)
	ip_address_cidr = models.CharField(max_length=100, blank=True, null=True)
	description = models.TextField(blank=True, null=True)
	insert_date = models.DateTimeField(null=True)
	start_scan_date = models.DateTimeField(null=True)
	request_headers = models.JSONField(null=True, blank=True)
	project = models.ForeignKey(Project, on_delete=models.CASCADE, null=True, blank=False)

	def get_recent_scan_id(self):
		ScanHistory = apps.get_model('startScan.ScanHistory')
		obj = ScanHistory.objects.filter(domain__id=self.id).order_by('-id')
		if obj:
			return obj[0].id

	def __str__(self):
		return str(self.name)
