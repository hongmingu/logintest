from django.conf.urls import url
from .views import *

urlpatterns = [
    url(r'^$', views.accounts, name='renoauth/accounts'),

    url(r'^create/$', views.create, name='renoauth/create'),
    url(r'^create/email/confirm/$', views.create_email_confirm, name='renoauth/create_email_confirm'),
    url(r'^create/email/confirm/key/(?P<uidb36>[0-9A-Za-z]+)-(?P<key>.+)/$', views.create_email_confirm_key,
        name='renoauth/create_email_confirm_key'),
    url(r'^create/done/$', views.create_done, name='renoauth/create_done'),

    url(r'^login/$', views.log_in, name='renoauth/log_in'),
    url(r'^logout/$', views.log_out, name='renoauth/log_out'),
    url(r'^logout/done/$', views.log_out_done, name='renoauth/logout'),

    url(r'^username/change/$', views.username_change, name='renoauth/username_change'),
    url(r'^username/change/done/$', views.username_change_done, name='renoauth/username_change_done'),

    url(r'^password/change/$', views.password_change, name='renoauth/password_change'),
    url(r'^password/change/done/$', views.password_change_done, name='renoauth/password_change_done'),
    url(r'^password/reset/$', views.password_reset, name='renoauth/password_reset'),
    url(r'^password/reset/done/$', views.password_reset_done, name='renoauth/password_reset_done'),
    url(r'^password/reset/key/(?P<uidb36>[0-9A-Za-z]+)-(?P<key>.+)/$', views.password_reset_key,
        name='renoauth/password_reset_key'),
    url(r'^password/reset/key/done/$', views.password_reset_key_done, name='renoauth/password_reset_key_done'),

    url(r'^email/add/$', views.email_add, name='renoauth/email_add'),
    url(r'^email/add/key/(?P<uidb36>[0-9A-Za-z]+)-(?P<key>.+)/$', views.email_add_key, name='renoauth/email_add_key'),
    url(r'^email/add/key/done/$', views.email_add_key_done, name='renoauth/email_add_key_done'),

    url(r'^email/default/$', views.email_default, name='renoauth/email_default'),
    url(r'^email/remove/$', views.email_remove, name='renoauth/email_remove'),
]