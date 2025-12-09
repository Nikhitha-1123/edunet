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
    
    # Profile
    path('profile/', views.profile, name='profile'),
    
    # View Items
    path('view-lost/', views.view_lost, name='view_lost'),
    path('view-found/', views.view_found, name='view_found'),
    path('lost-item/<int:item_id>/', views.lost_item_detail, name='lost_item_detail'),
    path('found-item/<int:item_id>/', views.found_item_detail, name='found_item_detail'),
    
    # Chat
    path('chat/lost/<int:item_id>/', views.chat_lost, name='chat_lost'),
    path('chat/found/<int:item_id>/', views.chat_found, name='chat_found'),
    
    # Edit/Delete
    path('edit-lost/<int:item_id>/', views.edit_lost, name='edit_lost'),
    path('edit-found/<int:item_id>/', views.edit_found, name='edit_found'),
    path('delete-lost/<int:item_id>/', views.delete_lost, name='delete_lost'),
    path('delete-found/<int:item_id>/', views.delete_found, name='delete_found'),
    
    # Mark as Reunited
    path('mark-lost-reunited/<int:item_id>/', views.mark_lost_reunited, name='mark_lost_reunited'),
    path('mark-found-reunited/<int:item_id>/', views.mark_found_reunited, name='mark_found_reunited'),
]