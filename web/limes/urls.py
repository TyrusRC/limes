from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import include, path

from limes.health import healthz
from limes.views import serve_protected_media
from sso import views as sso_views

urlpatterns = [
    path('healthz', healthz, name='healthz'),
    path(
        'admin/',
        admin.site.urls),
    path(
        '',
        include('dashboard.urls')),
    path(
        'scanEngine/',
        include('scanEngine.urls')),
    path(
        '',
        include('reporting.urls')),
    path('remediation/', include('remediation.urls')),
    path(
        'scan/',
        include('startScan.urls')),
    path(
        '',
        include('memberships.urls')),
    path(
        '',
        include('sso.urls')),
    path(
        'login/',
        sso_views.PasswordLoginView.as_view(),
        name='login'),
    path(
        'logout/',
        auth_views.LogoutView.as_view(template_name='base/logout.html'),
        name='logout'),
    path(
        'api/',
        include(
            'api.urls',
            'api')),
    path(
        'media/<path:path>', 
        serve_protected_media, 
        name='serve_protected_media'
    ),
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
# ] + static(settings.MEDIA_URL, document_root=settings.LIMES_RESULTS) + \
    
