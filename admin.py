from django.contrib import admin
from .models import *

# Register your models here.
admin.site.register(UserExtension)
admin.site.register(UserSubEmail)
admin.site.register(UserSubUsername)
admin.site.register(UserEmailAuthToken)
admin.site.register(UserDeleteTimer)

'''
class TestModelAdmin(admin.ModelAdmin):
    fields = ('description', 'updated', 'created')


class TestModelLogAdmin(admin.ModelAdmin):
    fields = ('description', 'status', 'created')


admin.site.register(TestModel, TestModelAdmin)
admin.site.register(TestModelLog, TestModelLogAdmin)

'''
admin.site.register(TestModel_2)
admin.site.register(TestModelLog_2)
