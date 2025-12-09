from django.db import models
from django.contrib.auth.models import User

# Create your models here.
class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    profile_picture = models.ImageField(upload_to='profile_pics/', blank=True, null=True)
    phone = models.CharField(max_length=15, blank=True)
    
    def __str__(self):
        return self.user.username


class lostitem(models.Model):
    CATEGORY_CHOICES = [
        ('Electronics', 'Electronics'),
        ('Documents', 'Documents'),
        ('Accessories', 'Accessories'),
        ('Clothing', 'Clothing'),
        ('Others', 'Others'),
    ]
    item_name = models.CharField(max_length=200)
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES, default='Others')
    description = models.TextField(blank=True)
    lost_place = models.CharField(max_length=200)
    lost_date = models.DateField()
    owner_name = models.CharField(max_length=150)
    phone_number = models.CharField(max_length=15)
    item_image = models.ImageField(upload_to='lost_items/', blank=True, null=True)
    security_question = models.CharField(max_length=255, blank=True)
    security_answer = models.CharField(max_length=255, blank=True)
    is_verified = models.BooleanField(default=False)
    is_reunited = models.BooleanField(default=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    

class founditem(models.Model):
    CATEGORY_CHOICES = [
        ('Electronics', 'Electronics'),
        ('Documents', 'Documents'),
        ('Accessories', 'Accessories'),
        ('Clothing', 'Clothing'),
        ('Others', 'Others'),
    ]
    item_name = models.CharField(max_length=200)
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES, default='Others')
    description = models.TextField(blank=True)
    found_place = models.CharField(max_length=200)
    found_date = models.DateField()
    finder_name = models.CharField(max_length=150)
    phone_number = models.CharField(max_length=15)
    item_image = models.ImageField(upload_to='found_items/', blank=True, null=True)
    is_reunited = models.BooleanField(default=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)


class Message(models.Model):
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_messages')
    lost_item = models.ForeignKey(lostitem, on_delete=models.CASCADE, null=True, blank=True)
    found_item = models.ForeignKey(founditem, on_delete=models.CASCADE, null=True, blank=True)
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['timestamp']


class Notification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    message = models.CharField(max_length=255)
    link = models.CharField(max_length=255, blank=True)
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']


class SuccessStory(models.Model):
    lost_item = models.ForeignKey(lostitem, on_delete=models.CASCADE, null=True, blank=True)
    found_item = models.ForeignKey(founditem, on_delete=models.CASCADE, null=True, blank=True)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='owner_stories')
    finder = models.ForeignKey(User, on_delete=models.CASCADE, related_name='finder_stories')
    testimonial = models.TextField()
    reunion_image = models.ImageField(upload_to='success_stories/', blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_featured = models.BooleanField(default=False)
    
    class Meta:
        ordering = ['-created_at']
