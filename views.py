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
from django.core.validators import validate_email
from django.contrib.auth import get_user_model
from django.conf import settings
from .utils import *
from .token import *
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.template.loader import render_to_string
from django.db import IntegrityError
from django.contrib.sites.shortcuts import get_current_site

# Create your models here.


def emailsignin(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(username=username, password=password)
        if user is not None:


            login(request, user)
            return JsonResponse({'hello': 'emailcheck'})
        else:
            return HttpResponse('로그인실패')
    else:
        form = LoginForm()
        return render(request, 'signin.html', {'form':form})


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


def create(request):
    if request.method == 'POST':

        form = UserCreateForm(request.POST)

        username = form.data['username']
        email = form.data['email']
        password = form.data['password']
        password_confirm = form.data['password_confirm']

        match_username = re.match('^[a-zA-Z0-9._]+$', username)
        match_email = re.match('[^@]+@[^@]+\.[^@]+', email)
        validate_email(email)

        if not match_username:
            data = {
                'username': username,
                'email': email,
            }
            wrong = {'message': 'It\'s unavailable username'}
            form = UserCreateForm(data)
            return render(request, 'renoauth/create.html', {'form': form, 'wrong': wrong})
        if len(username) > 30:
            data = {
                'username': username,
                'email': email,
            }
            wrong = {'message': 'username cannot over 30 characters'}
            form = UserCreateForm(data)
            return render(request, 'renoauth/create.html', {'form': form, 'wrong': wrong})
        if not match_email:
            data = {
                'username': username,
                'email': email,
            }
            wrong = {'message': 'It\'s unavailable email'}
            form = UserCreateForm(data)
            return render(request, 'renoauth/create.html', {'form': form, 'wrong': wrong})

        if len(email) > 255:
            data = {
                'username': username,
                'email': email,
            }
            wrong = {'message': 'email cannot over 255 characters'}
            form = UserCreateForm(data)
            return render(request, 'renoauth/create.html', {'form': form, 'wrong': wrong})

        if not password == password_confirm:
            data = {
                'username': username,
                'email': email,
            }
            wrong = {'message': 'both passwords you submitted are not the same'}
            form = UserCreateForm(data)
            return render(request, 'renoauth/create.html', {'form': form, 'wrong': wrong})
        if len(password) > 128:
            data = {
                'username': username,
                'email': email,
            }
            wrong = {'message': 'password is too long'}
            form = UserCreateForm(data)
            return render(request, 'renoauth/create.html', {'form': form, 'wrong': wrong})

        if form.is_valid():

            id_number = make_id()

            user_create = User.objects.create_user(
                username=id_number,
                password=form.cleaned_data['password'],
                is_active=False,
            )

            user_extension = UserExtension.objects.create(
                user=user_create,
                status=0,
            )

            user_sub_email = UserSubEmail.objects.create(
                user_extension=user_extension,
                email=form.cleaned_data['email'],
                status=0,
            )
            UserSubUsername.objects.create(
                user_extension=user_extension,
                username=form.cleaned_data['username'],
                status=0,
            )
            result = None
            while result is None:
                try:
                    uid = urlsafe_base64_encode(force_bytes(user_create.pk))
                    token = account_activate_token.make_token(user_create)

                    UserAuthToken.objects.create(
                        email=user_sub_email,
                        uid=uid,
                        token=token,
                    )
                    result = 1
                except IntegrityError as e:
                    if 'unique constraint' in e.message:
                        pass
                    else:
                        wrong = {'message': 'Some Bug occurred'}
                        render(request, 'error.html', wrong)

            current_site = get_current_site(request)
            subject = 'Activate Your MySite Account'

            '''
            user = form.save(commit=False)
            user.is_active = False
            user.save()
            '''

            message = render_to_string('account_activation_email.html', {
                'user': user_create,
                'domain': current_site.domain,
                'uid': uid,
                'token': token,
            })
            user_create.email_user(subject, message)

            login(request, user_create)

            return redirect('account_activation_sent')

        else:
            data = {
                'username': username,
                'email': email,
            }
            form = UserCreateForm(data)
            wrong = {'message': 'There is something wrong'}
            return render(request, 'renoauth/create.html', {'form': form, 'wrong': wrong})
    else:
        form = UserCreateForm()
        return render(request, 'renoauth/create.html', {'form': form})


def create_email_confirm(request):
    return


def create_email_confirm_key(request):
    return


def create_done(request):
    return


def log_in(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(username=username, password=password)
        if user is not None:
            login(request, user)
            username = user.username
            useremail = user.email
            userpass = user.password
            return HttpResponse('유저이름'+username+'유저이메일'+useremail+'유저비밀번호'+userpass)
        else:
            return HttpResponse('로그인실패')
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
