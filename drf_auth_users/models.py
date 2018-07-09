# -*- coding: utf-8 -*-
from django.contrib import auth
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.db import models
from django.utils.timezone import now
from rest_framework.authtoken.models import Token


class UserRole(models.Model):
    """
        Maintains roles available in the system
    """

    # name of the user role
    name = models.CharField(max_length=20)


class UserManager(BaseUserManager):
    """
        User manager class to handle user creation
    """

    def create_user(self, email, password=None, **extra_fields):
        """
            Creates a new User
              - Normalizes the email
              - Also creates a new auth token for the user
        """

        # Check if email is provided
        if not email:
            raise ValueError('User must have a valid email')

        # Normalize the provided email
        email = self.normalize_email(email)

        # Creating user object
        user = self.model(email=email, is_active=True, **extra_fields)
        # # setting user password
        user.set_password(password)
        # # saving user in database
        user.save()

        # Creating auth token for the user
        # token = Token.objects.create(user=user)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """
            Creates a superuser
        """
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser):
    """
        Maintain user and its attributes
    """
    # first name of the user
    first_name = models.CharField(max_length=200, null=True)
    # last name of the user
    last_name = models.CharField(max_length=200, null=True)
    # email id of the user
    email = models.CharField(max_length=200, null=True, unique=True)
    # email id of the user
    username = models.CharField(max_length=200, null=True)
    # role of the user (foreign key to UserRole model)
    user_role = models.ForeignKey(
        UserRole, on_delete=models.CASCADE, null=True)
    # indicates if the user is active or not
    is_active = models.BooleanField(default=True)
    # indicates if the user's email is verified or not
    is_email_verified = models.BooleanField(default=False)
    # the date when the user was created
    created = models.DateTimeField(default=now)
    # the date when the user object was last modified
    last_modified = models.DateTimeField(auto_now=True)
    # the date when the user last logged in
    last_login = models.DateTimeField(null=True)

    # defines the user manager class for User
    objects = UserManager()

    # specifies the field that will be used as username by django
    # drf_auth_users framework
    USERNAME_FIELD = 'email'

    def get_full_name(self):
        """
            Returns the first_name plus the last_name, with a space in between.
        """
        full_name = '%s %s' % (self.first_name, self.last_name)
        return full_name.strip()

    def get_short_name(self):
        """
        Returns the short name for the user.
        """
        return self.first_name


class UserVerification(models.Model):

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    verification_key = models.CharField(max_length=100, blank=True)
    key_expires = models.DateTimeField()


class UserResetPassword(models.Model):

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    key = models.CharField(max_length=100, blank=True)
    key_expires = models.DateTimeField()


class OAuthUsers(models.Model):
    """
            Stores user data retrieved from OAuth provider
    """
    # first name of user in facebook
    first_name = models.CharField(max_length=200, null=True, blank=True)
    # last name of user in facebook
    last_name = models.CharField(max_length=200, null=True, blank=True)
    # the user id obtained from oauth provider
    oauth_user_id = models.CharField(unique=True, max_length=30)
    # oauth provider
    oauth_provider = models.ForeignKey(
        'OAuthProviders', on_delete=models.CASCADE)
    # the email id obtained from facebook
    email = models.EmailField(
        max_length=254,
        null=True,
        default=None)
    # user's access token retrieved from oauth provider (short-lived)
    access_token = models.TextField(max_length=800)
    # user's access token retrieved from oauth provider (long-lived)
    long_lived_access_token = models.TextField(max_length=800, null=True)
    # indicates if the user token is expired or not
    token_expired = models.BooleanField(default=False)
    # the date when the token will be expired
    token_expiration_time = models.DateTimeField(null=True)
    # the date when the user was created
    created = models.DateTimeField(default=now)
    # the date when any modification was made to user data
    last_modified = models.DateTimeField(auto_now=True)
    # the user to which this oauth user data belongs to
    user = models.ForeignKey(
        'User',
        on_delete=models.CASCADE)

    class Meta:
        # db_table = 'oauth_users'
        unique_together = ('oauth_user_id', 'oauth_provider')


class OAuthProviders(models.Model):
    """
        Oauth provider detail
    """

    # name of the oauth_providers role
    name = models.CharField(max_length=20)