from django.contrib import admin
from .models import *

# Register your models here.
admin.site.register(UserIDNumber)
admin.site.register(UserSubEmail)
admin.site.register(UserSubUsername)
admin.site.register(UserAuthToken)