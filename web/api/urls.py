from django.conf.urls import include, url
from django.urls import path
from rest_framework import routers

from .views import *
from .alert_rules import Integration, JiraTest, RuleDetail, RuleList, RuleTest
from .feed import DismissFeedItems
from .score_history import ScoreHistory
from .lookalikes import DecideLookalike, LookalikeList, LookalikeReport

app_name = 'api'
router = routers.DefaultRouter()
router.register(r'listDatatableAsset', AssetDatatableViewSet, basename='asset')
router.register(r'notifications', InAppNotificationManagerViewSet, basename='notification')

urlpatterns = [
    url('^', include(router.urls)),
    path(
        'add/assets/',
        AddAssets.as_view(),
        name='add_assets'),
    path('action/asset/confirm/', ConfirmAsset.as_view(), name='confirm_asset'),
    path('action/asset/reject/', RejectAsset.as_view(), name='reject_asset'),
    path('action/asset/rescan/', RescanAsset.as_view(), name='rescan_asset'),
    path('action/asset/fullscan/', FullScanAsset.as_view(), name='full_scan_asset'),
    path('action/asset/cadence/', SetAssetCadence.as_view(), name='set_asset_cadence'),
    path('action/asset/tags/', AssetTags.as_view(), name='asset_tags'),
    path('tags/', TagList.as_view(), name='tags'),
    path('tag_scores/', TagScores.as_view(), name='tag_scores'),
    path('asset_score/', AssetScore.as_view(), name='asset_score'),
    path('issues/', IssueList.as_view(), name='issues'),
    path('alert_rules/', RuleList.as_view(), name='alert_rules'),
    path('alert_rules/<int:pk>/', RuleDetail.as_view(), name='alert_rule'),
    path('alert_rules/<int:pk>/test/', RuleTest.as_view(), name='alert_rule_test'),
    path('alert_integration/', Integration.as_view(), name='alert_integration'),
    path('alert_integration/jira_test/', JiraTest.as_view(), name='alert_jira_test'),
    path('lookalikes/', LookalikeList.as_view(), name='lookalikes'),
    path('action/lookalike/decide/', DecideLookalike.as_view(), name='decide_lookalike'),
    path('action/lookalike/report/', LookalikeReport.as_view(), name='lookalike_report'),
    path('action/issue/waive/', WaiveIssue.as_view(), name='waive_issue'),
    path('action/issue/revoke/', RevokeIssueWaiver.as_view(), name='revoke_issue_waiver'),
    path('issue/evidence/', IssueEvidence.as_view(), name='issue_evidence'),
    path('issue/notes/', IssueNotes.as_view(), name='issue_notes'),
    path('action/feed/dismiss/', DismissFeedItems.as_view(), name='dismiss_feed_items'),
    path('score_history/', ScoreHistory.as_view(), name='score_history'),
    path('score_forecast/', ScoreForecast.as_view(), name='score_forecast'),
    path(
        'getFileContents/',
        GetFileContents.as_view(),
        name='getFileContents'),
    path(
        'action/stop/scan/',
        StopScan.as_view(),
        name='stop_scan'),
    path(
        'search/',
        UniversalSearch.as_view(),
        name='search'),
    # API for fetching currently ongoing scans and upcoming scans
    path(
        'scan_status/',
        ScanStatus.as_view(),
        name='scan_status'),
    path(
        'action/create/project',
        CreateProjectApi.as_view(),
        name='create_project'),
]

urlpatterns += router.urls
