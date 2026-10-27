from django.urls import path
from . import views

urlpatterns = [
    path(
        '<slug:slug>/history/scan',
        views.scan_history,
        name="scan_history"),
    path('<slug:slug>/assets', views.assets, name='assets'),
    path('<slug:slug>/issues', views.issues, name='issues'),
    path('<slug:slug>/lookalikes', views.lookalikes, name='lookalikes'),
]
