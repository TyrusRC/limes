from dashboard.models import *
from limes.common_func import *
from rest_framework import serializers
from scanEngine.models import *
from startScan.models import *
from targetApp.models import *
from dashboard.models import InAppNotification
from django.utils.http import url_has_allowed_host_and_scheme
from urllib.parse import urlsplit


def safe_redirect_link(url):
	"""Notification click target: a same-site relative path or an http(s) URL, else None (no javascript:, data:, //host)."""
	# browsers drop tabs/newlines inside URLs ('java\tscript:'), so any control character or space is refused
	if not url or any(c.isspace() or not c.isprintable() for c in url):
		return None
	if url_has_allowed_host_and_scheme(url, allowed_hosts=None):  # relative: no scheme and no host
		return url
	parts = urlsplit(url)
	return url if parts.scheme.lower() in ('http', 'https') and parts.netloc else None


class InAppNotificationSerializer(serializers.ModelSerializer):
	class Meta:
		model = InAppNotification
		fields = [
			'id', 
			'title', 
			'description', 
			'icon', 
			'is_read', 
			'created_at', 
			'notification_type', 
			'status',
			'redirect_link',
			'open_in_new_tab',
			'project'
		]
		read_only_fields = ['id', 'created_at']

	def get_project_name(self, obj):
		return obj.project.name if obj.project else None

	def to_representation(self, instance):
		data = super().to_representation(instance)
		data['redirect_link'] = safe_redirect_link(data.get('redirect_link'))
		return data


class MinimalUserSerializer(serializers.ModelSerializer):
	"""
		Serializer for User model
		Purpose of this serializer is to return minimal information about user
		Related to report by @RaDiTZz0
	"""
	class Meta:
		model = User
		fields = ['username']


class ScanHistorySerializer(serializers.ModelSerializer):

	vulnerability_count = serializers.SerializerMethodField('get_vulnerability_count')
	current_progress = serializers.SerializerMethodField('get_progress')
	completed_time = serializers.SerializerMethodField('get_total_scan_time_in_sec')
	elapsed_time = serializers.SerializerMethodField('get_elapsed_time')
	completed_ago = serializers.SerializerMethodField('get_completed_ago')
	initiated_by = MinimalUserSerializer(read_only=True)

	class Meta:
		model = ScanHistory
		fields = [
			'id',
			'vulnerability_count',
			'current_progress',
			'completed_time',
			'elapsed_time',
			'completed_ago',
			'start_scan_date',
			'scan_status',
			'results_dir',
			'celery_ids',
			'tasks',
			'stop_scan_date',
			'error_message',
			'domain',
			'scan_type',
			'initiated_by'
		]
		depth = 1

	def get_vulnerability_count(self, scan_history):
		if scan_history.get_vulnerability_count:
			return scan_history.get_vulnerability_count()

	def get_progress(self, scan_history):
		return scan_history.get_progress()

	def get_total_scan_time_in_sec(self, scan_history):
		return scan_history.get_total_scan_time_in_sec()

	def get_elapsed_time(self, scan_history):
		return scan_history.get_elapsed_time()

	def get_completed_ago(self, scan_history):
		return scan_history.get_completed_ago()


class AssetSerializer(serializers.ModelSerializer):
    parent_value = serializers.CharField(source='parent.value', read_only=True, default=None)
    technologies = serializers.SlugRelatedField(many=True, read_only=True, slug_field='name')
    ip_addresses = serializers.SlugRelatedField(many=True, read_only=True, slug_field='address')
    tags = serializers.SlugRelatedField(many=True, read_only=True, slug_field='name')
    vuln_count = serializers.IntegerField(read_only=True, default=0)
    monitor = serializers.SerializerMethodField()
    found_by = serializers.SerializerMethodField()
    active = serializers.SerializerMethodField()

    def get_active(self, obj):
        from limes import monitor
        return monitor.is_active(obj)

    def get_monitor(self, obj):
        from limes import monitor
        return monitor.monitor_state(obj)

    def get_found_by(self, obj):
        from limes import monitor
        return monitor.found_by(obj)

    class Meta:
        model = Asset
        fields = ['id', 'kind', 'value', 'parent', 'parent_value', 'scope_tier', 'active_authorized', 'state',
                  'first_seen', 'last_seen', 'missed_count', 'http_status', 'page_title', 'webserver',
                  'content_type', 'content_length', 'response_time', 'cname', 'is_cdn', 'cdn_name',
                  'screenshot_path', 'sources', 'decision_reason', 'technologies', 'ip_addresses',
                  'tags', 'vuln_count', 'enrichment', 'confidence', 'confidence_detail', 'cadence_tier',
                  'last_resolved_at', 'monitor', 'found_by', 'active']
