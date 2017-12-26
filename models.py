from django.db import models
from django.utils.encoding import python_2_unicode_compatible
from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from django.conf import settings


# Create your models here.

@python_2_unicode_compatible
class UserExtension(models.Model):

    user = models.OneToOneField(User)

    status = models.PositiveSmallIntegerField(default=0)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "UserExtend for %s" % self.user


@python_2_unicode_compatible
class UserIDNumber(models.Model):

    user_extension = models.ForeignKey(UserExtension)

    id_number = models.CharField(max_length=30, unique=True)

    status = models.PositiveSmallIntegerField(default=0)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "UserIDNumber for %s" % self.user_extension


@python_2_unicode_compatible
class UserSubUsername(models.Model):

    user_extension = models.ForeignKey(UserExtension)

    username = models.CharField(max_length=30, unique=True)

    status = models.PositiveSmallIntegerField(default=0)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "UserUsername for %s" % self.user_extension


@python_2_unicode_compatible
class UserSubEmail(models.Model):
    user_extension = models.ForeignKey(UserExtension)
    email = models.EmailField(max_length=255)

    status = models.PositiveSmallIntegerField(default=0)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "UserSubEmail for %s" % self.user_extension


@python_2_unicode_compatible
class UserAuthToken(models.Model):

    email = models.ForeignKey(UserSubEmail)

    uid = models.CharField(max_length=64)
    token = models.CharField(max_length=34)

    sent = models.DateTimeField(null=True)
    viewed = models.DateTimeField(null=True)

    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "AuthToken for %s" % self.email

