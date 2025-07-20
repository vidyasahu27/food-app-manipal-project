from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.conf import settings

def detect_user(user):
    redirect_url = ''
    if user.role == 1:
        redirect_url = 'restaurantDashboard'
    elif user.role == 2:
        redirect_url = 'customerDashboard'
    elif user.role is None and user.is_superadmin:
        redirect_url = 'admin'
    return redirect_url

def send_email(request, user, email_for):
    email_templates = {
        'VERIFICATION_EMAIL': {
            'subject': 'Please Activate your account',
            'template': 'accounts/emails/account_verification_email.html'
        },
        'RESET_PASSWORD_EMAIL': {
            'subject': 'Reset Password Link',
            'template': 'accounts/emails/reset_password_email.html'
        }
    }
    from_email = settings.DEFAULT_EMAIL_FROM
    current_site = get_current_site(request)
    mail_subject = email_templates[email_for]['subject']
    message = render_to_string(email_templates[email_for]['template'], {
        'user': user,
        'domain': current_site,
        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        'token': default_token_generator.make_token(user),
    })
    to_email = user.email
    mail = EmailMessage(mail_subject, message, to=[to_email], from_email=from_email)
    mail.send()

def send_reset_password_email(request, user):
    from_email = settings.DEFAULT_EMAIL_FROM
    current_site = get_current_site(request)
    mail_subject = 'Reset Password Link'
    message = render_to_string('accounts/emails/reset_password_email.html', {
        'user': user,
        'domain': current_site,
        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        'token': default_token_generator.make_token(user),
    })
    to_email = user.email
    mail = EmailMessage(mail_subject, message, to=[to_email], from_email=from_email)
    mail.send()