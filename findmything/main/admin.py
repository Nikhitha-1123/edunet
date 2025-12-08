from django.contrib import admin
from .models import lostitem, founditem
# Register your models here.
admin.site.register(lostitem)
admin.site.register(founditem)  