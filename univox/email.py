import random
import os

from django.core.mail import send_mail

def generate_confirmation_code():
    return str(random.randint(1000, 9999))

def send_confirmation_email(user, code):
    subject = 'Confirm your email'
    message = f'Your confirmation code is: {code}'
    from_email = os.environ.get("UNIVOX_EMAIL")
    recipient_list = [user.email]
    send_mail(subject, message, from_email, recipient_list)