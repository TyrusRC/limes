from django.conf.urls import include, url
from django.urls import path
from rest_framework import routers

from .views import *
from .lookalikes import DecideLookalike, LookalikeList, LookalikeReport

app_name = 'api'
router = routers.DefaultRouter()
router.register(r'listDatatableSubdomain', SubdomainDatatableViewSet)
router.register(r'listDatatableAsset', AssetDatatableViewSet, basename='asset')
router.register(r'listTargets', ListTargetsDatatableViewSet)
router.register(r'listSubdomains', SubdomainsViewSet)
router.register(r'listEndpoints', EndPointViewSet)
router.register(r'listVulnerability', VulnerabilityViewSet)
router.register(r'listInterestingSubdomains', InterestingSubdomainViewSet)
router.register(r'listInterestingEndpoints', InterestingEndpointViewSet)
router.register(r'listSubdomainChanges', SubdomainChangesViewSet)
router.register(r'listEndPointChanges', EndPointChangesViewSet)
router.register(r'listIps', IpAddressViewSet)
router.register(r'listActivityLogs', ListActivityLogsViewSet)
router.register(r'listScanLogs', ListScanLogsViewSet)
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
    path('lookalikes/', LookalikeList.as_view(), name='lookalikes'),
    path('action/lookalike/decide/', DecideLookalike.as_view(), name='decide_lookalike'),
    path('action/lookalike/report/', LookalikeReport.as_view(), name='lookalike_report'),
    path('action/issue/waive/', WaiveIssue.as_view(), name='waive_issue'),
    path('action/issue/revoke/', RevokeIssueWaiver.as_view(), name='revoke_issue_waiver'),
    path('issue/notes/', IssueNotes.as_view(), name='issue_notes'),
    path('score_forecast/', ScoreForecast.as_view(), name='score_forecast'),
    path(
        'add/target/',
        AddTarget.as_view(),
        name='addTarget'),
    path(
        'queryTechnologies/',
        ListTechnology.as_view(),
        name='listTechnologies'),
    path(
        'queryPorts/',
        ListPorts.as_view(),
        name='listPorts'),
    path(
        'queryIps/',
        ListIPs.as_view(),
        name='listIPs'),
    path(
        'queryInterestingSubdomains/',
        QueryInterestingSubdomains.as_view(),
        name='queryInterestingSubdomains'),
    path(
        'querySubdomains/',
        ListSubdomains.as_view(),
        name='querySubdomains'),
    path(
        'queryEndpoints/',
        ListEndpoints.as_view(),
        name='queryEndpoints'),
    path(
        'queryAllScanResultVisualise/',
        VisualiseData.as_view(),
        name='queryAllScanResultVisualise'),
    path(
        'queryTargetsWithoutOrganization/',
        ListTargetsWithoutOrganization.as_view(),
        name='queryTargetsWithoutOrganization'),
    path(
        'queryTargetsInOrganization/',
        ListTargetsInOrganization.as_view(),
        name='queryTargetsInOrganization'),
    path(
        'listOrganizations/',
        ListOrganizations.as_view(),
        name='listOrganizations'),
    path(
        'listEngines/',
        ListEngines.as_view(),
        name='listEngines'),
    path(
        'listSubScans/',
        ListSubScans.as_view(),
        name='listSubScans'),
    path(
        'listScanHistory/',
        ListScanHistory.as_view(),
        name='listScanHistory'),
    path(
        'listInterestingKeywords/',
        ListInterestingKeywords.as_view(),
        name='listInterestingKeywords'),
    path(
        'getFileContents/',
        GetFileContents.as_view(),
        name='getFileContents'),
    path(
        'tools/ip_to_domain/',
        IPToDomain.as_view(),
        name='ip_to_domain'),
    path(
        'tools/cve_details/',
        CVEDetails.as_view(),
        name='cve_details'),
    path(
        'action/subdomain/delete/',
        DeleteSubdomain.as_view(),
        name='delete_subdomain'),
    path(
        'action/vulnerability/delete/',
        DeleteVulnerability.as_view(),
        name='delete_vulnerability'),
    path(
        'action/rows/delete/',
        DeleteMultipleRows.as_view(),
        name='delete_rows'),
    path(
        'toggle/subdomain/important/',
        ToggleSubdomainImportantStatus.as_view(),
        name='toggle_subdomain'),
    path(
        'action/initiate/subtask/',
        InitiateSubTask.as_view(),
        name='initiate_subscan'),
    path(
        'action/stop/scan/',
        StopScan.as_view(),
        name='stop_scan'),
    path(
        'fetch/results/subscan/',
        FetchSubscanResults.as_view(),
        name='fetch_subscan_results'),
    path(
        'fetch/most_vulnerable/',
        FetchMostVulnerable.as_view(),
        name='fetch_most_vulnerable'),
    path(
        'fetch/most_common_vulnerability/',
        FetchMostCommonVulnerability.as_view(),
        name='fetch_most_common_vulnerability'),
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
