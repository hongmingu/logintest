from django.conf.urls import url
from renoauth import views


urlpatterns = [
    url(r'^$', views.accounts, name='accounts'),

    url(r'^create/$', views.create, name='create'),
    url(r'^create/done/$', views.create_done, name='create_done'),

    url(r'^create/recaptcha/$', views.create_recaptcha, name='create_recaptcha'),

    url(r'^create/email/confirm/$', views.create_email_confirm, name='create_email_confirm'),
    url(r'^create/email/confirm/key/(?P<uid>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        views.create_email_confirm_key, name='create_email_confirm_key'),
    url(r'^create/email/confirm/done/(?P<uid>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$', views.create_email_confirm_done, name='create_email_confirm_done'),


    url(r'^login/$', views.log_in, name='log_in'),
    url(r'^logout/$', views.log_out, name='log_out'),
    url(r'^logout/done/$', views.log_out_done, name='logout'),

    url(r'^username/change/$', views.username_change, name='username_change'),
    url(r'^username/change/done/$', views.username_change_done, name='username_change_done'),

    url(r'^password/change/$', views.password_change, name='password_change'),
    url(r'^password/change/done/$', views.password_change_done, name='password_change_done'),
    url(r'^password/reset/$', views.password_reset, name='password_reset'),
    url(r'^password/reset/done/$', views.password_reset_done, name='password_reset_done'),
    url(r'^password/reset/key/(?P<uidb36>[0-9A-Za-z]+)-(?P<key>.+)/$', views.password_reset_key,
        name='password_reset_key'),
    url(r'^password/reset/key/done/$', views.password_reset_key_done, name='password_reset_key_done'),

    url(r'^email/add/$', views.email_add, name='email_add'),
    url(r'^email/add/key/(?P<uidb36>[0-9A-Za-z]+)-(?P<key>.+)/$', views.email_add_key, name='email_add_key'),
    url(r'^email/add/key/done/$', views.email_add_key_done, name='email_add_key_done'),

    url(r'^email/default/$', views.email_default, name='email_default'),
    url(r'^email/remove/$', views.email_remove, name='email_remove'),
]