from django.urls import path

from remediation import api, notes_api

urlpatterns = [
    path('remediation/', api.RemediationList.as_view(), name='remediation_list'),
    path('remediation/create/', api.RemediationCreate.as_view(), name='remediation_create'),
    path('remediation/detail/', api.RemediationDetail.as_view(), name='remediation_detail'),
    path('remediation/status/', api.RemediationStatus.as_view(), name='remediation_status'),
    path('remediation/message/', api.RemediationMessagePost.as_view(), name='remediation_message'),
    path('notes/', notes_api.NoteList.as_view(), name='notes'),
    path('notes/create/', notes_api.NoteCreate.as_view(), name='note_create'),
    path('notes/delete/', notes_api.NoteDelete.as_view(), name='note_delete'),
    path('members/', api.Members.as_view(), name='members'),
    path('waivers/', api.WaiverList.as_view(), name='waivers'),
    path('action/waiver/decide/', api.WaiverDecide.as_view(), name='waiver_decide'),
    path('action/waiver/revoke/', api.WaiverRevoke.as_view(), name='waiver_revoke'),
]
