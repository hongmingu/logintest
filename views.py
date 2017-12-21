from django.shortcuts import render
from .forms import UserCreateForm, LoginForm
from django.contrib.auth.models import User
from django.contrib.auth import login, authenticate, logout
from django.shortcuts import redirect, render
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie
from django.core.mail import EmailMessage
import re


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
        match_username = re.match('^[a-zA-Z0-9._]+$', username)
        email = form.data['email']
        match_email = re.match('[^@]+@[^@]+\.[^@]+', email)
        password = form.data['password']
        password_confirm = form.data['password_confirm']

        if not match_username:
            return JsonResponse({'result': 'false', 'username': username, 'email': email, 'password': password, 'password_confirm': password_confirm})
        if len(username) > 30:
            return JsonResponse({'result': 'Too many', 'password': password})
        if not match_email:
            return JsonResponse({'result': len(email)})
        if len(email) > 255:
            return JsonResponse({'result': 'Too long'})
        if not password == password_confirm:
            return JsonResponse({'result': 'Password is not the same'})
        if len(password) > 128:
            return JsonResponse({'result': 'Password is too long'})

        if form.is_valid():
            new_user = User.objects.create_user(
                username=form.cleaned_data['username'], password=form.cleaned_data['password'],
                email=form.cleaned_data['email']
            )
            login(request, new_user)
            submit_data = {
                'username': username, 'email': email, 'password': password, 'password_confirm':password_confirm
            }
            return JsonResponse(submit_data)
        else:
            wrong = {'message': 'There is something wrong'}
            return render(request, 'renoauth/create.html', {'form': form, 'wrong': wrong})
    else:
        data = {
            'username': 'Hedddo',
            'email': 'tnalfkdtprtm@gkfrjdi.gksek'
        }
        form = UserCreateForm(data)
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
            userna = user.username
            useremail = user.email
            userpass = user.password
            return HttpResponse('/logincheck/'+userna+'<br>'+useremail+'<br>'+userpass)
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
