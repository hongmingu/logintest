from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.auth.backends import ModelBackend
from django.conf import settings
from .models import UserExtension, UserSubUsername, UserSubEmail

# Create your models here.


class EmailOrUsernameAuthBackend(ModelBackend):

    def authenticate(self, username=None, password=None):
        if '@' in username:
            user_object = UserSubEmail.objects.get(email=username)
            user = user_object.user_extension.user
            # kwargs = {'email': username}
        else:
            user_object = UserSubUsername.objects.get(username=username)
            user = user_object.user_extension.user
            kwargs = {'username': username}
        try:
            # user = User.objects.get(**kwargs)
            if user.check_password(password):
                return user
        except User.DoesNotExist:
            return None

