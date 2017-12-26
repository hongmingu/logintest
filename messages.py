from django.contrib.sites.shortcuts import get_current_site

USERNAME_UNAVAILABLE = 'username can be made of digit, alphabet, . or _'
USERNAME_OVER_30 = 'username cannot over 30 characters'
USERNAME_ALREADY_USED = 'This username is already used'

EMAIL_UNAVAILABLE = 'It\'s unavailable email'
EMAIL_OVER_255 = 'email is too long'
EMAIL_ALREADY_USED = 'This email is already used'
EMAIL_CONFIRMATION_EXTRA_ERROR = 'email confirmation goes wrong'
EMAIL_CONFIRMATION_SUBJECT = 'Email confirmation to activate your account'

PASSWORD_NOT_THE_SAME = 'both passwords you submitted are not the same'
PASSWORD_OVER_128 = 'password is too long'
PASSWORD_EQUAL_USERNAME = 'password cannot be the same as username'

CREATING_USER_EXTRA_ERROR = 'There is something wrong on creating user'
CREATING_USER_OVERALL_ERROR = 'There is something wrong'
