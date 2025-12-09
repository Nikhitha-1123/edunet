from django.contrib import admin
from .models import lostitem, founditem, UserProfile, Message, Notification, SuccessStory

admin.site.register(lostitem)
admin.site.register(founditem)
admin.site.register(UserProfile)
admin.site.register(Message)
admin.site.register(Notification)
admin.site.register(SuccessStory)