import datetime
import hashlib
import random

from django.utils import timezone

from drf_auth_users.models import UserVerification, UserResetPassword


def create_and_store_verification_key(email, user):
    salt = hashlib.sha1((str(random.random())).encode('utf-8')).hexdigest()[:5]
    verification_key = hashlib.sha1(
        (str(salt + email)).encode('utf-8')).hexdigest()
    from django.utils import timezone
    key_expires = timezone.now() + datetime.timedelta(days=7)
    if UserVerification.objects.filter(user_id=user.id).exists():
        user_verification = UserVerification.objects.get(user_id=user.id)
        user_verification.verification_key = verification_key
        user_verification.key_expires = key_expires
    else:
        user_verification = UserVerification(
            user=user,
            verification_key=verification_key,
            key_expires=key_expires)
    user_verification.save()
    return verification_key


def create_reset_password_key(user):
    salt = hashlib.sha1((str(random.random())).encode('utf-8')).hexdigest()[:5]
    key = hashlib.sha1(
        (str(salt + user.email)).encode('utf-8')).hexdigest()
    key_expires = timezone.now() + datetime.timedelta(hours=2)
    try:
        user_reset_password = UserResetPassword.objects.get(user_id=user.id)
        user_reset_password.key = key
        user_reset_password.key_expires = key_expires
    except UserResetPassword.DoesNotExist:
        user_reset_password = UserResetPassword(user=user,
                                                key=key,
                                                key_expires=key_expires)
    user_reset_password.save()
    return key
