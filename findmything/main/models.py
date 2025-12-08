from django.db import models

# Create your models here.
class lostitem(models.Model):
    item_name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    lost_place = models.CharField(max_length=200)
    lost_date = models.DateField()
    owner_name = models.CharField(max_length=150)
    phone_number = models.CharField(max_length=15)
    



class founditem(models.Model):
    item_name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    found_place = models.CharField(max_length=200)
    found_date = models.DateField()
    finder_name = models.CharField(max_length=150)
    phone_number = models.CharField(max_length=15)