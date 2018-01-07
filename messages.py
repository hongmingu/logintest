from django.contrib.sites.shortcuts import get_current_site

USERNAME_UNAVAILABLE = 'username can be made of digit, alphabet, . or _'
USERNAME_LENGTH_OVER_30 = 'You have to change username length'
USERNAME_ALREADY_USED = 'This username is already used'
USERNAME_BANNED = 'It\'s unavailable username'
USERNAME_OVER_5_CANNOT_DIGITS = 'If username is over 5 words, cannot be made of only digits'

EMAIL_UNAVAILABLE = 'It\'s unavailable email'
EMAIL_LENGTH_OVER_255 = 'You have to change email length'
EMAIL_ALREADY_USED = 'This email is already used'
EMAIL_CONFIRMATION_EXTRA_ERROR = 'email confirmation goes wrong'
EMAIL_CONFIRMATION_SUBJECT = 'Email confirmation to activate your account'

PASSWORD_NOT_THE_SAME = 'both passwords you submitted are not the same'
PASSWORD_LENGTH_PROBLEM = 'You have to change password length'
PASSWORD_EQUAL_USERNAME = 'password cannot be the same as username'
PASSWORD_BANNED = 'It\'s unavailable password'

CREATING_USER_EXTRA_ERROR = 'There is something wrong on creating user'
CREATING_USER_OVERALL_ERROR = 'There is something wrong'

RECAPTCHA_CONFIRM_NEED = 'Check that you are human'

KEY_NOT_EXIST = 'This key is unavailable'
KEY_EXPIRED = 'This key is expired'
KEY_ALREADY_VIEWED = 'This key is already expired'
KEY_CREATE_SUCCESS = 'Thanks for creating account'
KEY_OVERALL_FAILED = 'There is something wrong for key'

LOGIN_FAILED = 'Login has failed'
LOGIN_EMAIL_NOT_EXIST = 'Email does not exist'
LOGIN_USERNAME_NOT_EXIST = 'Username does not exist'

