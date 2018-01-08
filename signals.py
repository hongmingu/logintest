from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.utils.timezone import now
from .models import *

'''
@receiver(post_save, sender=TestModel_2)
def create_update_log(sender, instance, created, **kwargs):
    if created:
        TestModelLog_2.objects.create(description=instance.description, status=20)
    else:
        TestModelLog_2.objects.create(description=instance.description, status=33)


@receiver(post_delete, sender=TestModel_2)
def delete_log(sender, instance, **kwargs):
    TestModelLog_2.objects.create(description=instance.description, status=2038)
    
def save(self, commit=True):
    user = super(CustomFormThing, self).save(commit=False)
    #set some other attrs on user here ...
    user._some = 'some'
    user._other = 'other'
    if commit:
        user.save()

    return user

@receiver(post_save, sender=User)
def create_profile(sender, instance, created, **kwargs):
    some_id = getattr(instance, '_some', None)
    other_id = getattr(instance, '_other', None)

    if created:
'''

    # 여기 datetime 을 instance.updated 로 할지 now() 로 할지 결정해야한다 .