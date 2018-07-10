# Create your tasks here
from __future__ import absolute_import, unicode_literals
from celery import shared_task
from django.template.loader import get_template
from django.conf import settings
from drf_auth_users.models import User
from drf_auth_users.utils import create_and_store_verification_key
from emails.send_email import SendEmailWrapper


@shared_task
def send_verification_mail(user_id):
    user = User.objects.get(id=user_id)
    email_template = get_template(settings.VERIFICATION_EMAIL_TEMPLATE)

    verification_code = create_and_store_verification_key(user.email, user)

    email_context = {
        'first_name': user.first_name,
        'last_name': user.last_name,
        'verification_url': settings.FRONTEND_URL_FOR_EMAIL_VERIFICATION_HANDLE + verification_code
    }
    # Rendering email template with context
    email_body = email_template.render(email_context)

    # Call core email sending function
    ok, message_id = SendEmailWrapper \
        .send_email_core(from_email=settings.EMAIL_USERNAME,
                         recipient_list=[user.email],
                         subject='Verify your email',
                         body=email_body)

@shared_task
def send_reset_password_mail(user_id, key):
    user = User.objects.get(id=user_id)
    html_template = get_template(settings.PASSWORD_RESET_EMAIL_TEMPLATE)
    content_passed_to_template = {
        'first_name': user.first_name,
        'last_name': user.last_name,
        'reset_password_url': settings.FRONTEND_URL_FOR_PASSWORD_RESET_HANDLE + key + '&user_id=' + str(user_id)
    }
    html_content = html_template.render(content_passed_to_template)

    # Call core email sending function
    ok, message_id = SendEmailWrapper \
        .send_email_core(from_email=settings.EMAIL_USERNAME,
                         recipient_list=[user.email],
                         subject='Reset your password',
                         body=html_content)