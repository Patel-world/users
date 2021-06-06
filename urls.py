"""Defines url pattern for users"""

from . import views
from django.contrib.auth import views as auth_views

from django.urls import path


urlpatterns = [
    path('register', views.register_attempt, name="register_attempt"),
    path('login/', views.login_attempt, name="login_attempt"),
    path('token', views.token_send, name="token_send"),
    path('success', views.success, name='success'),
    path('verify/<auth_token>', views.verify, name="verify"),
    path('error', views.error_page, name="error"),
    path('email_does_not_exists', views.user_not_exist, name="user_not_exists"),
    path('change-password', views.change_password, name='change_password'),


    # #log out
    path('logout/', views.logout_view, name='logout'),
    #user registration


    path('password_reset', views.password_reset_request, name="pasword_reset")
]

