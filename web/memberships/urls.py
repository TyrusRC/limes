from django.urls import path

from . import views

urlpatterns = [
    path('<slug:slug>/members/', views.members, name='project_members'),
    path('<slug:slug>/members/add', views.member_add, name='project_member_add'),
    path('<slug:slug>/members/<int:member_id>/role', views.member_role, name='project_member_role'),
    path('<slug:slug>/members/<int:member_id>/remove', views.member_remove, name='project_member_remove'),
    path('<slug:slug>/members/api/', views.members_api, name='project_members_api'),
    path('<slug:slug>/members/api/<int:member_id>/', views.member_api, name='project_member_api'),
]
