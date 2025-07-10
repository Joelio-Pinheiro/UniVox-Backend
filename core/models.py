from django.db import models

class User(models.Model):
    name = models.CharField(max_length=50, unique=True)
    user_name = models.CharField(max_length=50, unique=True, blank=True)
    password = models.CharField(max_length=100)
    email = models.CharField(max_length=70, unique=True)
    description = models.CharField(max_length=200, blank=True)
    popularity_score = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    email_verified = models.BooleanField(default=False)

class EmailConfirmation(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    is_confirmed = models.BooleanField(default=False)

class PasswordReset(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    is_confirmed = models.BooleanField(default=False)