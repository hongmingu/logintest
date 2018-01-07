from django.apps import AppConfig


class CustomauthConfig(AppConfig):
    name = 'renoauth'

    def ready(self):
        import renoauth.signals
