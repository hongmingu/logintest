from django.shortcuts import render
from .forms import UserCreateForm, LoginForm
from .models import *
from django.contrib.auth.models import User
from django.contrib.auth import login, authenticate, logout
from django.shortcuts import redirect, render
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie
from django.core.mail import EmailMessage
import re
from django.core.exceptions import ValidationError
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
import urllib
import json
from renoauth import numbers
from renoauth import messages
from renoauth import banned

# Create your models here.

def test(request):
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
        #### recaptcha

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

        ##### banned username and password

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

        ###### Integrity UserSubEmail and UserSubUsername
        if UserSubEmail.objects.filter(email=email,
                                           status=numbers.USER_SUB_EMAIL_VERIFIED).exists() \
                or UserSubEmail.objects.filter(
                email=email, status=numbers.USER_SUB_EMAIL_VERIFIED_PRIMARY).exists():

            clue = {'message': messages.EMAIL_ALREADY_USED}
            form = UserCreateForm(data)
            return render(request, 'renoauth/create.html', {'form': form, 'clue': clue})

        if not UserSubUsername.objects.filter(username=username, status=numbers.USER_SUB_USERNAME_USING).exists():
            clue = {'message': messages.USERNAME_ALREADY_USED}

            form = UserCreateForm(data)
            return render(request, 'renoauth/create.html', {'form': form, 'clue': clue})
        ###### regex check

        ####### 8이상 숫자 허용 x
        if not match_username:
            clue = {'message': messages.USERNAME_UNAVAILABLE}
            form = UserCreateForm(data)
            return render(request, 'renoauth/create.html', {'form': form, 'clue': clue})
        if len(username) > 5 and username.isdigit():
            clue = {'message': messages.USERNAME_OVER_5_CANNOT_DIGITS}
            form = UserCreateForm(data)
            return render(request, 'renoauth/create.html', {'form': form, 'clue': clue})
        if len(username) > 30:
            clue = {'message': messages.USERNAME_OVER_30}
            form = UserCreateForm(data)
            return render(request, 'renoauth/create.html', {'form': form, 'clue': clue})
        if not match_email:
            clue = {'message': messages.EMAIL_UNAVAILABLE}
            form = UserCreateForm(data)
            return render(request, 'renoauth/create.html', {'form': form, 'clue': clue})
        if len(email) > 255:
            clue = {'message': messages.EMAIL_OVER_255}
            form = UserCreateForm(data)
            return render(request, 'renoauth/create.html', {'form': form, 'clue': clue})
        if not password == password_confirm:
            clue = {'message': messages.PASSWORD_NOT_THE_SAME}
            form = UserCreateForm(data)
            return render(request, 'renoauth/create.html', {'form': form, 'clue': clue})
        if len(password) > 128:
            clue = {'message': messages.PASSWORD_OVER_128}
            form = UserCreateForm(data)
            return render(request, 'renoauth/create.html', {'form': form, 'clue': clue})
        if username == password:
            clue = {'message': messages.PASSWORD_EQUAL_USERNAME}
            form = UserCreateForm(data)
            return render(request, 'renoauth/create.html', {'form': form, 'clue': clue})
        ##### then
        if form.is_valid():
            check_username_result = None
            while check_username_result is None:
                try:
                    id_number = make_id()
                    user_create = User.objects.create_user(
                        username=id_number,
                        password=form.cleaned_data['password'],
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

            user_extension = UserExtension.objects.create(
                user=user_create,
                status=numbers.USER_EXTENSION_USING_UNVERIFIED,
            )
            user_sub_email = UserSubEmail.objects.create(
                user_extension=user_extension,
                email=form.cleaned_data['email'],
                status=numbers.USER_SUB_EMAIL_UNVERIFIED,
            )
            UserSubUsername.objects.create(
                user_extension=user_extension,
                username=form.cleaned_data['username'],
                status=numbers.USER_SUB_USERNAME_USING,
            )

            uid = None
            token = None
            check_token_result = None
            while check_token_result is None:
                try:
                    uid = urlsafe_base64_encode(force_bytes(user_create.pk))
                    token = account_activation_token.make_token(user_create)
                    if not UserAuthToken.objects.filter(uid=uid, token=token).exists():
                        UserAuthToken.objects.create(
                            email=user_sub_email,
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
                'user': user_create,
                'domain': current_site.domain,
                'uid': uid,
                'token': token,
            })
            user_create.email_user(subject, message)

            login(request, user_create)

            return redirect('/')
        else:
            form = UserCreateForm(data)
            clue = {'message': messages.CREATING_USER_OVERALL_ERROR}
            return render(request, 'renoauth/create.html', {'form': form, 'clue': clue})
    else:
        form = UserCreateForm()
        return render(request, 'renoauth/create.html', {'form': form})


def email_key_send(request):
    return


def email_key_confirm(request, uid, token):
    try:
        user_authtoken = UserAuthToken.objects.get(uid=uid, token=token)
    except (ValueError):
        clue = {'message': messages.KEY_NOT_EXIST}
        return render(request, 'renoauth/email_key_confirm.html', {'clue': clue})

    if user_authtoken.viewed is not None:
        clue = {'message': messages.KEY_ALREADY_VIEWED}
        return render(request, 'renoauth/email_key_confirm.html', {'clue': clue})

    try:
        uid = force_text(urlsafe_base64_decode(uid))
        user = User.objects.get(pk=uid)
        user_subemail = user_authtoken.email
        user_extension = user.userextension
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
        user_subemail = None
        user_authtoken = None
        user_extension = None

    if user is not None and user_subemail is not None and user_authtoken is not None and user_extension is not None \
            and account_activation_token.check_token(user, token):

        if not now() - user_authtoken.created <= timedelta(seconds=60*10):
            clue = {'message': messages.KEY_EXPIRED}
            return render(request, 'renoauth/email_key_confirm.html', {'clue': clue})

        user.is_active = True
        user_subemail.status = numbers.USER_SUB_EMAIL_VERIFIED_PRIMARY
        user_extension.status = numbers.USER_EXTENSION_USING_VERIFIED
        user_authtoken.viewed = now()
        user.save()
        user_subemail.save()
        user_extension.save()
        user_authtoken.save()
        clue = {'message': messages.KEY_CREATE_SUCCESS}
        return render(request, 'renoauth/email_key_confirm.html', {'clue': clue})
    else:
        clue = {'message': messages.KEY_OVERALL_FAILED}
        return render(request, 'renoauth/email_key_confirm.html', {'clue': clue})


def log_in(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        username = request.POST['username']
        if '@' in username:
            user_object = UserSubEmail.objects.get(email=username)
            if user_object is None:
                clue = {'message': messages.LOGIN_FAILED}
                return render(request, 'main.html', {'clue': clue})
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

        password = request.POST['password']
        user = authenticate(username=username, password=password)
        if user is not None:
            login(request, user)
            username = user.username
            user_extension = user.userextension
            user_subemail = UserSubEmail.objects.get(user_extension=user_extension,
                                                    status=numbers.USER_SUB_EMAIL_VERIFIED_PRIMARY)
            user_subusername = UserSubUsername.objects.get(user_extension=user_extension,
                                                           status=numbers.USER_SUB_USERNAME_USING)
            return redirect('/')
        else:
            clue = {'message': messages.LOGIN_FAILED}
            return render(request, 'main.html', {'clue': clue})
    else:
        form = LoginForm()
        return render(request, 'signin.html', {'form':form})


def log_out(request):
    return


def log_out_done(request):
    return


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
    return


@ensure_csrf_cookie
def email_add_key(request):
    if request.method == 'POST':
        if request.is_ajax():
            request_email = request.POST['email']
            email_to = []
            email_to.append(request_email)
            email = EmailMessage('hhhhhhho', 'ddddddddddddddddi', from_email='mingu1@60noname.com', to=email_to)
            email.send()
            return JsonResponse({'your_email': request_email})
    elif request.method == 'GET':
        return render(request, 'email_send.html')


def email_add_key_done(request):
    return


def email_default(request):
    return


def email_remove(request):
    return
