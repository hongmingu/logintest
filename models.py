from django.db import models
from django.utils.encoding import python_2_unicode_compatible
from django.contrib.auth import get_user_model
from django.contrib.auth.models import User
from django.conf import settings


# Create your models here.

@python_2_unicode_compatible
class UserExtension(models.Model):

    user = models.OneToOneField(User, on_delete=models.CASCADE)

    verified = models.BooleanField(default=False)

    activated = models.BooleanField(default=False)

    updated = models.DateTimeField(auto_now=True)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "UserExtend for %s" % self.user


@python_2_unicode_compatible
class UserDeleteTimer(models.Model):

    user_extension = models.OneToOneField(UserExtension, on_delete=models.CASCADE)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "UserDeleteTimer for %s" % self.user_extension.user


@python_2_unicode_compatible
class UserSubUsername(models.Model):

    user_extension = models.OneToOneField(UserExtension)

    username = models.CharField(max_length=30, unique=True)

    updated = models.DateTimeField(auto_now=True)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "UserUsername for %s" % self.user_extension.user


@python_2_unicode_compatible
class UserSubEmail(models.Model):
    user_extension = models.ForeignKey(UserExtension, on_delete=models.CASCADE)

    email = models.EmailField(max_length=255)

    primary = models.BooleanField(default=False)
    verified = models.BooleanField(default=False)

    updated = models.DateTimeField(auto_now=True)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "UserSubEmail for %s" % self.user_extension.user


@python_2_unicode_compatible
class UserEmailAuthToken(models.Model):

    email = models.ForeignKey(UserSubEmail, on_delete=models.CASCADE)

    uid = models.CharField(max_length=64)
    token = models.CharField(max_length=34)

    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "AuthToken for %s" % self.email


@python_2_unicode_compatible
class UserPasswordAuthToken(models.Model):

    user_extension = models.ForeignKey(UserSubEmail, on_delete=models.CASCADE)

    uid = models.CharField(max_length=64)
    token = models.CharField(max_length=34)

    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "PasswordAuthToken for %s" % self.email


@python_2_unicode_compatible
class TestModel_2(models.Model):
    description = models.CharField(max_length=34)

    updated = models.DateTimeField(auto_now=True)
    created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "TestModel %s" % self.description


@python_2_unicode_compatible
class TestModelLog_2(models.Model):
    description = models.CharField(max_length=34)
    test_foreignkey = models.ForeignKey(TestModel_2, related_name='test_foreignkey_1', null=True, blank=True, on_delete=models.DO_NOTHING)
    test_foreignkey_2 = models.ForeignKey(TestModel_2, related_name='test_foreignkey_2', null=True, blank=True, on_delete=models.DO_NOTHING)

    status = models.PositiveSmallIntegerField(default=0)
    datetime = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return "TestModelLog %s" % self.description

