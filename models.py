from django.db import models
from django.utils.encoding import python_2_unicode_compatible
from django.contrib.auth import get_user_model
from django.conf import settings


# Create your models here.

UserModel = get_user_model()


class AuthToken(models.Model):

    email = models.ForeignKey(UserModel)
    token = models.CharField(max_length=64, unique=True)

    send = models.DateTimeField(null=True)
    create = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = _("email confirmation")
        verbose_name_plural = _("email confirmations")

    def __str__(self):
        return "confirmation for %s" % self.email_address


@python_2_unicode_compatible
class EmailAddress(models.Model):

    user = models.ForeignKey(allauth_app_settings.USER_MODEL,
                             verbose_name=_('user'),
                             on_delete=models.CASCADE)
    email = models.EmailField(unique=app_settings.UNIQUE_EMAIL,
                              max_length=app_settings.EMAIL_MAX_LENGTH,
                              verbose_name=_('e-mail address'))
    verified = models.BooleanField(verbose_name=_('verified'), default=False)
    primary = models.BooleanField(verbose_name=_('primary'), default=False)

    objects = EmailAddressManager()

    class Meta:
        verbose_name = _("email address")
        verbose_name_plural = _("email addresses")
        if not app_settings.UNIQUE_EMAIL:
            unique_together = [("user", "email")]

    def __str__(self):
        return "%s (%s)" % (self.email, self.user)

    def set_as_primary(self, conditional=False):
        old_primary = EmailAddress.objects.get_primary(self.user)
        if old_primary:
            if conditional:
                return False
            old_primary.primary = False
            old_primary.save()
        self.primary = True
        self.save()
        user_email(self.user, self.email)
        self.user.save()
        return True

    def send_confirmation(self, request=None, signup=False):
        if app_settings.EMAIL_CONFIRMATION_HMAC:
            confirmation = EmailConfirmationHMAC(self)
        else:
            confirmation = EmailConfirmation.create(self)
        confirmation.send(request, signup=signup)
        return confirmation

    def change(self, request, new_email, confirm=True):
        """
        Given a new email address, change self and re-confirm.
        """
        with transaction.atomic():
            user_email(self.user, new_email)
            self.user.save()
            self.email = new_email
            self.verified = False
            self.save()
            if confirm:
                self.send_confirmation(request)

