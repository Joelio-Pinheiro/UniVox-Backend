from django.db import models

class User(models.Model):
    name = models.CharField(max_length=50)
    password = models.CharField(max_length=100)
    email = models.CharField(max_length=70)
    contact_number = models.CharField(max_length=11)
    created_at = models.DateTimeField(auto_now_add=True)