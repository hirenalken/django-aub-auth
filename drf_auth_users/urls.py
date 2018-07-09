from django.conf.urls import url
from django.urls import include

from rest_framework.urlpatterns import format_suffix_patterns

from drf_auth_users import views
from drf_auth_users.views import UserPasswordResetRequest, UserPasswordResetStatus, UserUpdatePassword

"""
    zo_backend/users URL Configuration
"""
urlpatterns = [
    url(r'^users/register/$', views.UserRegistration.as_view()),
    url(r'^users/login/$', views.UserLogin.as_view()),
    url(r'^users/oauth/$', views.UserOAuth.as_view()),
    url(r'^users/(?P<userid>[0-9]+)/verify/(?P<verification_key>\w+)/$',
                   views.UserEmailVerification.as_view()),
    url(r'^users/password_reset_request/$', UserPasswordResetRequest.as_view()),
    url(r'^users/(?P<user_id>[0-9]+)/password_reset_status/(?P<key>\w+)/$', UserPasswordResetStatus.as_view()),
    url(r'^users/(?P<user_id>[0-9]+)/update_password/$', UserUpdatePassword.as_view()),
    url('', include('social_django.urls', namespace='social'))
]


urlpatterns = format_suffix_patterns(urlpatterns)