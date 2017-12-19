from django.shortcuts import render
from .forms import UserForm, LoginForm
from django.contrib.auth.models import User
from django.contrib.auth import login, authenticate, logout
from django.shortcuts import redirect, render
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie
from django.core.mail import EmailMessage


def emailsignin(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(username=username, password=password)
        if user is not None:


            login(request, user)
            return JsonResponse({'hello':'emailcheck' })
        else:
            return HttpResponse('로그인실패')
    else:
        form = LoginForm()
        return render(request, 'signin.html', {'form':form})


def email_send(request):
    return


def accounts(request):
    return


def create(request):
    if request.method == 'POST':
        form = UserForm(request.POST)
        if form.is_valid():
            new_user = User.objects.create_user(
                username=form.cleaned_data['username'], password=form.cleaned_data['password'], email=form.cleaned_data['email']
            )
            login(request, new_user)
            return JsonResponse(form.cleaned_data)
    else:
        form = UserForm
        return render(request, 'adduser.html', {'form': form})


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


def username_change_done(request):
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
