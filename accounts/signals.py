from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from .models import User, UserProfile

@receiver(post_save, sender=User)
def post_save_create_profile_receiver(sender, instance, created, **kwargs):
    print(created)
    if created:
        UserProfile.objects.create(user=instance)
        print("user profile is created")
    else:
        try:
            profile = UserProfile.objects.get(user=instance)
            profile.save()
        except:
            #create the user
            UserProfile.objects.create(user=instance)
        print("user is updated")