import random
from django.core.mail import send_mail
from django.conf import settings
from .models import User


def send_otp_via_mail(email):
    subject = 'Verification OTP Received'
    otp = random.randint(100000, 999999)
    message = f'Your OTP is {otp}'
    email_from = settings.EMAIL_HOST 
    send_mail(subject, message, email_from, [email])
    user = User.objects.get(email=email)
    user.otp = otp
    user.save()

def password_reset_mail(email, uid, token):
    subject = 'Reset Your Password'
    link = f'http://127.0.0.1:8000/api/user/reset-password/{uid}/{token}'
    message = f"Please reset your password- {link}"
    email_from = settings.EMAIL_HOST
    send_mail(subject, message, email_from, [email])
    # user = User.objects.get(email=email)
    # user.link = link
    # user.save()