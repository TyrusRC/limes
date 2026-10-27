from django.urls import path

from . import views

urlpatterns = [
    path('<slug:slug>/reports/', views.reports, name='reports'),
    path('<slug:slug>/reports/summary', views.executive_summary, name='executive_summary'),
    path('<slug:slug>/reports/export/issues.csv', views.export_issues, name='export_issues'),
    path('<slug:slug>/reports/export/assets.csv', views.export_assets, name='export_assets'),
    path('<slug:slug>/reports/generate', views.generate_now, name='report_generate'),
    path('<slug:slug>/reports/runs/<int:run_id>/download', views.download, name='report_download'),
    path('<slug:slug>/reports/runs/<int:run_id>/delete', views.run_delete, name='report_run_delete'),
    path('<slug:slug>/reports/schedules/new', views.schedule_form, name='report_schedule_new'),
    path('<slug:slug>/reports/schedules/<int:schedule_id>/edit', views.schedule_form, name='report_schedule_edit'),
    path('<slug:slug>/reports/schedules/<int:schedule_id>/toggle', views.schedule_toggle, name='report_schedule_toggle'),
    path('<slug:slug>/reports/schedules/<int:schedule_id>/delete', views.schedule_delete, name='report_schedule_delete'),
    path('<slug:slug>/reports/schedules/<int:schedule_id>/run', views.schedule_run, name='report_schedule_run'),
    path('<slug:slug>/reports/templates/new', views.template_form, name='report_template_new'),
    path('<slug:slug>/reports/templates/<int:template_id>/edit', views.template_form, name='report_template_edit'),
    path('<slug:slug>/reports/templates/<int:template_id>/delete', views.template_delete, name='report_template_delete'),
]
