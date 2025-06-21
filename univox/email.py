import random
import os

from django.core.mail import send_mail
from django.utils.html import strip_tags
from django.utils import timezone

#Verification code process
CODE_EXPIRATION_TIME = 300.0 #in seconds

def generate_confirmation_code():
    return str(random.randint(1000, 9999))

def is_code_expired(create_date):
    timeDiff = timezone.now() - create_date

    return timeDiff.total_seconds() > CODE_EXPIRATION_TIME

#For new accounts email verification
def send_confirmation_email(user, code):
    subject = 'Confirm your email'
    message = f'<p>Your confirmation code is: <strong>{code}</strong></p>'
    from_email = os.environ.get("UNIVOX_EMAIL")
    recipient_list = [user.email]
    send_mail(subject, strip_tags(message), from_email, recipient_list, html_message=message)

#For password reset verification
def send_password_confirmation_code(user, code):
    subject = "Password reset"
    message = f'<p>Your confirmation code is: <strong>{code}</strong></p>'
    from_email = os.environ.get("UNIVOX_EMAIL")
    recipient_list = [user.email]
    send_mail(subject, strip_tags(message), from_email, recipient_list, html_message=message)

#------------