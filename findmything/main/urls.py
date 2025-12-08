"""FindMyThing URL Configuration"""
from django.contrib import admin
from django.urls import path
from main import views

urlpatterns = [
    # Root — redirect to login/dashboard based on auth
    path('', views.index, name='index'),
    
    # Authentication
    path('login/', views.login_view, name='login'),
    path('signup/', views.signup_view, name='signup'),
    path('logout/', views.logout_view, name='logout'),
    path('google/login/', views.google_login, name='google_login'),
    path('google/callback/', views.google_callback, name='google_callback'),
    
    # Dashboard
    path('dashboard/', views.dashboard, name='dashboard'),
    
    # Reports
    path('report-lost/', views.report_lost, name='report_lost'),
    path('report-found/', views.report_found, name='report_found'),
    
    # Legacy routes
    path('lost_item/', views.lost_item, name='lost_item_legacy'),
    path('found_item/', views.found_item, name='found_item_legacy'),
    path('litem/', views.litem, name='litem'),
    path('fitem/', views.fitem, name='fitem'),
]