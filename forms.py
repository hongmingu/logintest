from django import forms
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from django.conf import settings



class UserCreateForm(forms.ModelForm):
    username = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control ', 'placeholder': 'Username'}))
    email = forms.EmailField(widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'email'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Password'}))
    password_confirm = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Password_confirm'}))

    class Meta:
        model = User
        fields = ['username', 'email', 'password']


class LoginForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['username', 'password']