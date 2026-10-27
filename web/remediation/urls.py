from django.urls import path

from remediation import views

urlpatterns = [
    path('<slug:slug>/', views.remediation_list, name='remediation_list_page'),
    path('<slug:slug>/new', views.remediation_new, name='remediation_new'),
    path('<slug:slug>/waivers', views.waivers_page, name='waivers_page'),
    path('<slug:slug>/waivers/<int:pk>/', views.waiver_detail, name='waiver_detail'),
    path('<slug:slug>/<int:pk>/', views.remediation_detail, name='remediation_detail'),
]
