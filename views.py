from .forms import *
from .models import *
from django.contrib.auth.models import User
from django.contrib.auth import login, authenticate, logout
from django.shortcuts import redirect, render
from django.shortcuts import get_object_or_404, get_list_or_404
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie
from django.core.mail import EmailMessage
import re
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth import get_user_model
from django.conf import settings
from .utils import *
from .token import *
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.template.loader import render_to_string
from django.db import IntegrityError
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_text
from django.utils.http import urlsafe_base64_decode
from django.utils.timezone import now, timedelta
import json
from renoauth import messages
from renoauth import banned
from renoauth import text
from renoauth import status
import urllib
from urllib.parse import urlparse
import ssl
from bs4 import BeautifulSoup
from django.core.mail import send_mail
from django.http import HttpResponse, HttpResponseNotFound, Http404
# Create your models here.


def get_redirected_url(url):
    context = ssl._create_unverified_context()
    result = urllib.request.urlopen(url, context=context).geturl()
    return result


def test2(request):
    if request.method == 'POST':

        if request.is_ajax():
            # time.sleep(2)
            testmodel2 = None
            try:
                testmodel2 = TestModel_2.objects.get(description='aqgggqq')
            except TestModel_2.DoesNotExist:
                print('hey there is no matching query')

                pass
            testmodel3 = None

            return HttpResponse(type(testmodel2))
    else:
        return render(request, 'renoauth/test2.html')


def test(request):
    if request.method == 'POST':

        if request.is_ajax():
            HttpResponse('hey')
            url = "https://goo.gl/7Gt5nQ"
            url2 = "http://f-st.co/THHI6hC"
            url_refresh_sample = "http://www.isthe.com/chongo/tech/comp/cgi/redirect.html"
            url_google = "http://google.com"
            redirecturl = get_redirected_url(url_refresh_sample)

            ssl._create_default_https_context = ssl._create_unverified_context
            html = urllib.request.urlopen(url_refresh_sample)
            bs_object = BeautifulSoup(html.read(), "html.parser")

            bs_refresh = bs_object.find('meta', attrs={'http-equiv': 'Refresh'})
            #refresh 랑 Refresh 구별해야함 그리고 smtp, ftp 그외 는 따로 분류할수도 있어야함.
            bs_refresh_content = bs_refresh['content']
            got_url = bs_refresh_content.partition('=')[2]
            bs_pretty = bs_refresh.prettify()

            return HttpResponse(got_url)
    else:
        return render(request, 'renoauth/test.html')


def accounts(request):
    return render(request, 'renoauth/accounts.html')


'''
password = models.CharField(_('password'), max_length=128)

class AbstractUser(AbstractBaseUser, PermissionsMixin):
    """
    An abstract base class implementing a fully featured User model with
    admin-compliant permissions.
    Username and password are required. Other fields are optional.
    """
    username_validator = UnicodeUsernameValidator()

    username = models.CharField(
        _('username'),
        max_length=150,
        unique=True,
        help_text=_('Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.'),
        validators=[username_validator],
        error_messages={
            'unique': _("A user with that username already exists."),
        },
    )
    first_name = models.CharField(_('first name'), max_length=30, blank=True)
    last_name = models.CharField(_('last name'), max_length=150, blank=True)
    email = models.EmailField(_('email address'), blank=True)
    is_staff = models.BooleanField(
        _('staff status'),
        default=False,
        help_text=_('Designates whether the user can log into this admin site.'),
    )
    is_active = models.BooleanField(
        _('active'),
        default=True,
        help_text=_(
            'Designates whether this user should be treated as active. '
            'Unselect this instead of deleting accounts.'
        ),
    )
    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)

    objects = UserManager()

    EMAIL_FIELD = 'email'
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']

    class Meta:
        verbose_name = _('user')
        verbose_name_plural = _('users')
        abstract = True

    def clean(self):
        super().clean()
        self.email = self.__class__.objects.normalize_email(self.email)

    def get_full_name(self):
        """
        Return the first_name plus the last_name, with a space in between.
        """
        full_name = '%s %s' % (self.first_name, self.last_name)
        return full_name.strip()

    def get_short_name(self):
        """Return the short name for the user."""
        return self.first_name

    def email_user(self, subject, message, from_email=None, **kwargs):
        """Send an email to this user."""
        send_mail(subject, message, from_email, [self.email], **kwargs)
'''

'''
user = form.save(commit=False)
user.is_active = False
user.save()
'''


def create(request):
    if request.method == 'POST':

        form = UserCreateForm(request.POST)

        username = form.data['username']
        email = form.data['email']
        password = form.data['password']
        password_confirm = form.data['password_confirm']
        data = {
            'username': username,
            'email': email,
        }

        # recaptcha part begin

        recaptcha_response = request.POST.get('g-recaptcha-response')
        url = 'https://www.google.com/recaptcha/api/siteverify'
        values = {
            'secret': settings.GOOGLE_RECAPTCHA_SECRET_KEY,
            'response': recaptcha_response
        }
        recaptcha_data = urllib.parse.urlencode(values).encode()
        recaptcha_req = urllib.request.Request(url, data=recaptcha_data)
        recaptcha_response = urllib.request.urlopen(recaptcha_req)
        recaptcha_result = json.loads(recaptcha_response.read().decode())

        if not recaptcha_result['success']:
            clue = {'message': messages.RECAPTCHA_CONFIRM_NEED}
            form = UserCreateForm(data)
            return render(request, 'renoauth/create.html', {'form': form, 'clue': clue})

        # banned username and password

        match_ban = [nm for nm in banned.BANNED_USERNAME_LIST if nm in username]
        if match_ban:
            clue = {'message': messages.USERNAME_BANNED}
            form = UserCreateForm(data)
            return render(request, 'renoauth/create.html', {'form': form, 'clue': clue})

        if password in banned.BANNED_PASSWORD_LIST:
            clue = {'message': messages.PASSWORD_BANNED}
            form = UserCreateForm(data)
            return render(request, 'renoauth/create.html', {'form': form, 'clue': clue})

        match_username = re.match('^([A-Za-z0-9_](?:(?:[A-Za-z0-9_]|(?:\.(?!\.))){0,28}(?:[A-Za-z0-9_]))?)$', username)
        match_email = re.match('[^@]+@[^@]+\.[^@]+', email)

        # Integrity UserSubEmail and UserSubUsername
        user_sub_email = None
        try:
            user_sub_email = UserSubEmail.objects.get(email=email, verified=True)
        except UserSubEmail.DoesNotExist:
            pass

        # set user_delete_timer None
        user_delete_timer = None

        if user_sub_email is not None:
            user_extension = user_sub_email.user_extension
            try:
                user_delete_timer = UserDeleteTimer.objects.get(user_extension=user_extension)
            except UserDeleteTimer.DoesNotExist:
                pass

        if user_delete_timer is not None and now() - user_delete_timer.created > timedelta(days=30):
            # user_delete_timer is over 30days
            user_delete_timer.user_extension.user.delete()
            user_sub_email = None

        if user_sub_email is not None and user_sub_email.verified is True:
            clue = {'message': messages.EMAIL_ALREADY_USED}
            form = UserCreateForm(data)
            return render(request, 'renoauth/create.html', {'form': form, 'clue': clue})

        user_sub_username = None
        try:
            user_sub_username = UserSubUsername.objects.get(username=username)
        except UserSubUsername.DoesNotExist:
            pass

        # set user_delete_timer None
        user_delete_timer = None

        if user_sub_username is not None:
            user_extension = user_sub_username.user_extension
            try:
                user_delete_timer = UserDeleteTimer.objects.get(user_extension=user_extension)
            except UserDeleteTimer.DoesNotExist:
                pass

        if user_delete_timer is not None and now() - user_delete_timer.created > timedelta(days=30):
            user_delete_timer.user_extension.user.delete()
            user_sub_username = None

        if user_sub_username is not None:
            clue = {'message': messages.USERNAME_ALREADY_USED}
            form = UserCreateForm(data)
            return render(request, 'renoauth/create.html', {'form': form, 'clue': clue})
        # regex check

        # In username, more 5 characters and only digits prevent
        if not match_username:
            clue = {'message': messages.USERNAME_UNAVAILABLE}
            form = UserCreateForm(data)
            return render(request, 'renoauth/create.html', {'form': form, 'clue': clue})
        if len(username) > 5 and username.isdigit():
            clue = {'message': messages.USERNAME_OVER_5_CANNOT_DIGITS}
            form = UserCreateForm(data)
            return render(request, 'renoauth/create.html', {'form': form, 'clue': clue})
        if len(username) > 30:
            clue = {'message': messages.USERNAME_LENGTH_OVER_30}
            form = UserCreateForm(data)
            return render(request, 'renoauth/create.html', {'form': form, 'clue': clue})
        if not match_email:
            clue = {'message': messages.EMAIL_UNAVAILABLE}
            form = UserCreateForm(data)
            return render(request, 'renoauth/create.html', {'form': form, 'clue': clue})
        if len(email) > 255:
            clue = {'message': messages.EMAIL_LENGTH_OVER_255}
            form = UserCreateForm(data)
            return render(request, 'renoauth/create.html', {'form': form, 'clue': clue})
        if not password == password_confirm:
            clue = {'message': messages.PASSWORD_NOT_THE_SAME}
            form = UserCreateForm(data)
            return render(request, 'renoauth/create.html', {'form': form, 'clue': clue})
        if len(password) > 128 or len(password) < 6:
            clue = {'message': messages.PASSWORD_LENGTH_PROBLEM}
            form = UserCreateForm(data)
            return render(request, 'renoauth/create.html', {'form': form, 'clue': clue})
        if username == password:
            clue = {'message': messages.PASSWORD_EQUAL_USERNAME}
            form = UserCreateForm(data)
            return render(request, 'renoauth/create.html', {'form': form, 'clue': clue})

        # Then, go to is_valid below
        if form.is_valid():
            check_username_result = None
            new_user_create = None
            new_username = form.cleaned_data['username']
            new_password = form.cleaned_data['password']
            new_email = form.cleaned_data['email']
            while check_username_result is None:
                try:
                    id_number = make_id()
                    new_user_create = User.objects.create_user(
                        username=id_number,
                        password=new_password,
                        is_active=False,
                    )
                    check_username_result = 1

                except IntegrityError as e:
                    if 'unique constraint' in e.message:
                        pass
                    else:
                        clue = {'message': messages.CREATING_USER_EXTRA_ERROR}
                        form = UserCreateForm(data)
                        return render(request, 'renoauth/create.html', {'form': form, 'clue': clue})

            new_user_extension_create = None

            if new_user_create is not None:
                new_user_extension_create = UserExtension.objects.create(
                    user=new_user_create,
                    verified=False,
                )

            new_user_sub_email_create = None
            new_user_sub_username = None

            if new_user_extension_create is not None:

                new_user_sub_email_create = UserSubEmail.objects.create(
                    user_extension=new_user_extension_create,
                    email=new_email,
                    verified=False,
                    primary=True,
                )

                if user_sub_email is not None and user_sub_email.verified is False:
                    user_sub_email.delete()

                new_user_sub_username = UserSubUsername.objects.create(
                    user_extension=new_user_extension_create,
                    username=new_username,
                )

            uid = None
            token = None
            check_token_result = None
            if new_user_sub_email_create is not None:

                while check_token_result is None:
                    try:
                        uid = urlsafe_base64_encode(force_bytes(new_user_create.pk))
                        token = account_activation_token.make_token(new_user_create)
                        if not UserAuthToken.objects.filter(uid=uid, token=token).exists():
                            UserAuthToken.objects.create(
                                email=new_user_sub_email_create,
                                uid=uid,
                                token=token,
                            )
                        check_token_result = 1
                    except IntegrityError as e:
                        if 'unique constraint' in e.message:
                            pass
                        else:
                            clue = {'message': messages.EMAIL_CONFIRMATION_EXTRA_ERROR}
                            form = UserCreateForm(data)
                            return render(request, 'renoauth/create.html', {'form': form, 'clue': clue})

            current_site = get_current_site(request)
            subject = '[' + current_site.domain + ']' + messages.EMAIL_CONFIRMATION_SUBJECT

            message = render_to_string('renoauth/account_activation_email.html', {
                'user': new_user_sub_username,
                'domain': current_site.domain,
                'uid': uid,
                'token': token,
            })

            # Here needs variable of form.cleaned_data['email']?
            new_user_sub_email_list = [new_email]

            send_mail(
                subject=subject, message=message, from_email=text.DEFAULT_FROM_EMAIL,
                recipient_list=new_user_sub_email_list
            )

            login(request, new_user_create)

            return redirect('/')
        else:
            form = UserCreateForm(data)
            clue = {'message': messages.CREATING_USER_OVERALL_ERROR}
            return render(request, 'renoauth/create.html', {'form': form, 'clue': clue})
    else:
        form = UserCreateForm()
        return render(request, 'renoauth/create.html', {'form': form})


def email_key_confirm(request, uid, token):

    user_auth_token = None

    try:
        user_auth_token = UserAuthToken.objects.get(uid=uid, token=token)
    except UserAuthToken.DoesNotExist:
        clue = {'message': messages.KEY_NOT_EXIST}
        return render(request, 'renoauth/email_key_confirm.html', {'clue': clue})

    if user_auth_token is not None and not now() - user_auth_token.created <= timedelta(seconds=60*10):
        user_auth_token.delete()
        clue = {'message': messages.KEY_EXPIRED}
        return render(request, 'renoauth/email_key_confirm.html', {'clue': clue})

    try:
        uid = force_text(urlsafe_base64_decode(uid))
        user = User.objects.get(pk=uid)
        user_sub_email = user_auth_token.email
        user_extension = user.userextension
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
        user_sub_email = None
        user_auth_token = None
        user_extension = None

    if user is not None and user_sub_email is not None and user_auth_token is not None and user_extension is not None \
            and account_activation_token.check_token(user, token):

        user.is_active = True
        user_sub_email.verified = True

        user_extension.verified = False

        email = user_sub_email.email

        UserAuthToken.objects.filter(email__email=email).delete()
        UserSubEmail.objects.filter(email=email).exclude(user_extension=user_extension).delete()

        user.save()
        user_sub_email.save()
        user_extension.save()
        clue = {'message': messages.KEY_CONFIRM_SUCCESS}
        return render(request, 'renoauth/email_key_confirm.html', {'clue': clue})
    else:
        clue = {'message': messages.KEY_OVERALL_FAILED}
        return render(request, 'renoauth/email_key_confirm.html', {'clue': clue})


def log_in(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        username = form.data['username']
        user_sub_email = None
        user_sub_username = None
        user_delete_timer = None
        if '@' in username:
            try:
                user_sub_email = UserSubEmail.objects.get(email=username)
            except UserSubEmail.DoesNotExist:
                pass

            if user_sub_email is not None:
                try:
                    user_delete_timer = UserDeleteTimer.objects.get(user_extension=user_sub_email.user_extension)
                except UserDeleteTimer.DoesNotExist:
                    pass
                if user_delete_timer is not None:
                    if now() - user_delete_timer.created > timedelta(days=30):
                        user_delete_timer.user_extension.user.delete()
                        user_sub_email = None
                    else:
                        user_delete_timer.delete()

            if user_sub_email is None:
                clue = {'message': messages.LOGIN_EMAIL_NOT_EXIST}
                return render(request, 'main.html', {'form': form, 'clue': clue})

        else:
            try:
                user_sub_username = UserSubUsername.objects.get(username=username)
            except UserSubUsername.DoesNotExist:
                pass

            if user_sub_username is not None:
                try:
                    user_delete_timer = UserDeleteTimer.objects.get(user_extension=user_sub_username.user_extension)
                except UserDeleteTimer.DoesNotExist:
                    pass

                if user_delete_timer is not None:
                    if now() - user_delete_timer.created > timedelta(days=30):
                        user_delete_timer.user_extension.user.delete()
                        user_sub_username = None
                    else:
                        user_delete_timer.delete()

                if user_sub_username is None:
                    clue = {'message': messages.LOGIN_USERNAME_NOT_EXIST}
                    return render(request, 'main.html', {'form': form, 'clue': clue})

        password = form.data['password']

        user = authenticate(username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect('/')
        else:
            data = {
                'username': username,
                'password': password,
            }
            form = LoginForm(data)
            clue = {'message': messages.LOGIN_FAILED}
            return render(request, 'main.html', {'form': form, 'clue': clue})
    else:
        form = LoginForm()
        return render(request, 'signin.html', {'form': form})


def log_out(request):
    if request.method == "POST":
        logout(request)
        return redirect('/')
    else:
        return render(request, 'log_out')


def username_change(request):
    return


def username_change_done(request):
    return


def password_change(request):
    return


def password_change_done(request):
    return


def password_reset(request):
    return


def password_reset_done(request):
    return


def password_reset_key(request):
    return


def password_reset_key_done(request):
    return


def email_add(request):
    if request.method == 'POST':
        if request.is_ajax():
            new_email = request.POST['email']
            if new_email is not None:

                match_email = re.match('[^@]+@[^@]+\.[^@]+', new_email)
                if not match_email:
                    clue = None
                    clue['success'] = False
                    clue['message'] = messages.EMAIL_UNAVAILABLE
                    return JsonResponse(clue)
                if len(new_email) > 255:
                    clue = None
                    clue['success'] = False
                    clue['message'] = messages.EMAIL_LENGTH_OVER_255
                    return JsonResponse(clue)

                email_exist = None
                try:
                    email_exist = UserSubEmail.objects.get(email=new_email, verified=True)
                except UserSubEmail.DoesNotExist:
                    pass

                if email_exist is not None:
                    clue = None
                    clue['success'] = False
                    clue['message'] = messages.EMAIL_ALREADY_USED
                    return JsonResponse(clue)
                else:
                    user = request.user
                    user_extension = user.userextension

                    new_user_sub_email_add = UserSubEmail.objects.create(
                        user_extension=user_extension,
                        email=new_email,
                        verified=False,
                        primary=False,
                    )

                    uid = None
                    token = None
                    check_token_result = None
                    if new_user_sub_email_add is not None:

                        while check_token_result is None:
                            try:
                                uid = urlsafe_base64_encode(force_bytes(user.pk))
                                token = account_activation_token.make_token(user)
                                if not UserAuthToken.objects.filter(uid=uid, token=token).exists():
                                    UserAuthToken.objects.create(
                                        email=new_user_sub_email_add,
                                        uid=uid,
                                        token=token,
                                    )
                                check_token_result = 1
                            except IntegrityError as e:
                                if 'unique constraint' in e.message:
                                    pass
                                else:
                                    clue = {'message': messages.EMAIL_CONFIRMATION_EXTRA_ERROR}
                                    return render(request, 'renoauth/accounts_change.html', {'clue': clue})
                    new_user_sub_email_list = [new_email]
                    current_site = get_current_site(request)

                    message = render_to_string('renoauth/account_activation_email.html', {
                        'user': user_extension,
                        'domain': current_site.domain,
                        'uid': uid,
                        'token': token,
                    })

                    subject = '[' + current_site.domain + ']' + messages.EMAIL_CONFIRMATION_SUBJECT

                    send_mail(
                        subject=subject, message=message, from_email=text.DEFAULT_FROM_EMAIL,
                        recipient_list=new_user_sub_email_list
                    )
                    result = None
                    result['success'] = True
                    result['message'] = messages.EMAIL_ADDED
                    return JsonResponse(result)
            else:
                result = None
                result['success'] = False
                result['message'] = messages.BAD_ACCESS
                return JsonResponse(result)
    else:
        raise Http404(messages.BAD_ACCESS)


@ensure_csrf_cookie
def email_key_send(request):
    if request.method == 'POST':
        if request.is_ajax():
            new_email = request.POST['email']
            if new_email is not None:
                new_user_sub_email = None
                try:
                    new_user_sub_email = UserSubEmail.objects.get(email=new_email,
                                                                  user_extension=request.user.userextension,
                                                                  verified=False)
                except UserSubEmail.DoesNotExist:
                    pass
                if new_user_sub_email is not None:

                    user = request.user
                    user_extension = user.userextension

                    uid = None
                    token = None
                    check_token_result = None

                    while check_token_result is None:
                        try:
                            uid = urlsafe_base64_encode(force_bytes(user.pk))
                            token = account_activation_token.make_token(user)
                            if not UserAuthToken.objects.filter(uid=uid, token=token).exists():
                                UserAuthToken.objects.create(
                                    email=new_user_sub_email,
                                    uid=uid,
                                    token=token,
                                )
                            check_token_result = 1
                        except IntegrityError as e:
                            if 'unique constraint' in e.message:
                                pass
                            else:
                                clue = {'message': messages.EMAIL_CONFIRMATION_EXTRA_ERROR}
                                return render(request, 'renoauth/accounts_change.html', {'clue': clue})
                    new_user_sub_email_list = [new_email]
                    current_site = get_current_site(request)

                    message = render_to_string('renoauth/account_activation_email.html', {
                        'user': user_extension,
                        'domain': current_site.domain,
                        'uid': uid,
                        'token': token,
                    })

                    subject = '[' + current_site.domain + ']' + messages.EMAIL_CONFIRMATION_SUBJECT

                    send_mail(
                        subject=subject, message=message, from_email=text.DEFAULT_FROM_EMAIL,
                        recipient_list=new_user_sub_email_list
                    )
                    result = None
                    result['success'] = True
                    result['message'] = messages.EMAIL_SENT
                    return JsonResponse(result)
                else:
                    clue = None
                    clue['success'] = False
                    clue['message'] = messages.EMAIL_CANNOT_SEND
                    return JsonResponse(clue)
            else:
                result = None
                result['success'] = False
                result['message'] = messages.BAD_ACCESS
                return JsonResponse(result)

    else:
        result = None
        result['success'] = False
        result['message'] = messages.BAD_ACCESS
        return JsonResponse(result)


def email_remove(request):
    if request.method == "POST":
        if request.is_ajax():
            target_email = request.POST['email']
            if target_email is not None:
                target_user_sub_email = None
                try:
                    target_user_sub_email = UserSubEmail.objects.get(user_extension=request.user.userextension,
                                                                     email=target_email)
                except UserSubEmail.DoesNotExist:
                    pass

                if target_user_sub_email is not None:
                    if target_user_sub_email.primary is True:
                        result = None
                        result['success'] = False
                        result['message'] = messages.EMAIL_PRIMARY_CANNOT_BE_REMOVED
                        return JsonResponse(result)
                    else:
                        target_user_sub_email.delete()
                        result = None
                        result['success'] = True
                        result['message'] = messages.EMAIL_REMOVED
                        return JsonResponse(result)
                else:
                    result = None
                    result['success'] = False
                    result['message'] = messages.EMAIL_NOT_EXIST
                    return JsonResponse(result)
    else:
        result = None
        result['success'] = False
        result['message'] = messages.BAD_ACCESS
        return JsonResponse(result)


def email_primary(request):
    if request.method == "POST":
        if request.is_ajax():
            email = request.POST['email']
            if email is not None:
                user = request.user
                user_extension = user.userextension
                target_email = None
                try:
                    target_email = UserSubEmail.objects.get(email=email, user_extension=user_extension)
                except UserSubEmail.DoesNotExist:
                    pass

                if target_email is not None:
                    if target_email.primary is not True:
                        user_sub_email_already_primary = None
                        try:
                            user_sub_email_already_primary = UserSubEmail.objects.get(user_extension=user_extension,
                                                                                      primary=True)
                        except UserSubEmail.DoesNotExist:
                            pass
                        if user_sub_email_already_primary is not None:
                            user_sub_email_already_primary.primary = False
                            user_sub_email_already_primary.save()

                        target_email.primary = True
                        target_email.save()

                        result = None
                        result['success'] = True
                        result['message'] = messages.EMAIL_GET_PRIMARY
                        return JsonResponse(result)
                    else:
                        result = None
                        result['success'] = False
                        result['message'] = messages.EMAIL_ALREADY_PRIMARY
                        return JsonResponse(result)
                else:
                    result = None
                    result['success'] = False
                    result['message'] = messages.EMAIL_NOT_EXIST
                    return JsonResponse(result)
            else:
                result = None
                result['success'] = False
                result['message'] = messages.BAD_ACCESS
                return JsonResponse(result)
        else:
            result = None
            result['success'] = False
            result['message'] = messages.BAD_ACCESS
            return JsonResponse(result)
    else:
        result = None
        result['success'] = False
        result['message'] = messages.BAD_ACCESS
        return JsonResponse(result)

