from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.auth.backends import ModelBackend
from django.conf import settings
from .models import UserExtend, UserUsername, UserEmail

# Create your models here.

class EmailOrUsernameAuthBackend(ModelBackend):

    def authenticate(self, username=None, password=None):
        if '@' in username:
            # Userobject = UserEmail.objects.get(email=username)
            # user = Userobject.user_extend.user
            kwargs = {'email': username}
        else:
            # Userobject = UserUsername.objects.get(username=username)
            # user = Userobject.user_extend.user
            kwargs = {'username': username}
        try:
            user = User.objects.get(**kwargs)
            if user.check_password(password):
                return user
        except User.DoesNotExist:
            return None

