from django.contrib import admin
from django.urls import include, path

from . import alert_rules_page, views

urlpatterns = [
    path(
        '<slug:slug>/',
        views.index,
        name='scan_engine_index'),
    path(
        '<slug:slug>/add/',
        views.add_engine,
        name='add_engine'),
    path(
        '<slug:slug>/delete/<int:id>',
        views.delete_engine,
        name='delete_engine_url'),
    path(
        '<slug:slug>/update/<int:id>',
        views.update_engine,
        name='update_engine'),
    path(
        '<slug:slug>/tool_settings',
        views.tool_specific_settings,
        name='tool_settings'),
    path(
        '<slug:slug>/limes_settings',
        views.limes_settings,
        name='limes_settings'),
    path(
        '<slug:slug>/notification_settings',
        views.notification_settings,
        name='notification_settings'),
    path(
        '<slug:slug>/alert_rules',
        alert_rules_page.alert_rules_page,
        name='alert_rules_page'),
    path(
        '<slug:slug>/proxy_settings',
        views.proxy_settings,
        name='proxy_settings'),
]
