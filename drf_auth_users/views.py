import requests
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from django.conf import settings
from social_core.exceptions import MissingBackend
from social_django.utils import load_strategy, load_backend
from social_django.views import NAMESPACE

from drf_auth_users import responses, custom_codes, tasks
from drf_auth_users.custom_codes import USER_REGISTRATION_SUCCESSFUL_1100, USER_LOGIN_SUCCESSFUL_1101
from drf_auth_users.models import User, OAuthUsers, UserVerification, UserResetPassword
from drf_auth_users.serializers import UserRegistrationSerializer, UserLoginSerializer, UserOAuthSerializer, \
    UserOAuthRequestSerializer, UserSerializer
from drf_auth_users.utils import create_reset_password_key


class UserRegistration(APIView):
    def post(self, request):
        """
            User login API

            *  Request sample for User registration/login request

                    {
                            "first_name" : string,
                            "last_name" : string,
                            "email" : string,
                            "password": string
                    }


            ** Success **


                {
                    "success": true,
                    "message": "User registration successful",
                    "payload": {
                        "user": {
                            "id": 6,
                            "first_name": "Hiren",
                            "last_name": "Patel",
                            "email": "hiren45@yopmail.com",
                            "username": null,
                            "is_active": true,
                            "is_email_verified": false,
                            "created": "2018-07-02T10:15:33.799237Z",
                            "last_modified": "2018-07-02T10:15:33.906028Z",
                            "last_login": "2018-07-02T10:15:33.905223Z",
                            "user_role": null
                        },
                        "token": "837f83ac0675546dc1de8a8ee89451eae07ac82f"
                    }
                }


            ** Failure **


            *  Invalid request


                {
                    "success": false,
                    "message": "Bad request",
                    "payload": {
                        "email": [
                            "Enter a valid email address."
                        ]
                    },
                    "error_code": 400
                }

            *  Account already exists with same email


                {
                    "success": false,
                    "message": "Account with same email already exists",
                    "payload": {},
                    "error_code": 1002
                }
        """

        serializer = UserRegistrationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                responses.generate_failure_response(custom_codes.BAD_REQUEST_400,
                                                    payload=serializer.errors), status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email=request.data['email']).exists():
            return Response(
                responses.generate_failure_response(custom_codes.ACCOUNT_ALREADY_EXISTS_1002,
                                                    payload=serializer.errors), status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create_user(email=request.data['email'], password=request.data['password'])
        user.first_name = request.data['first_name']
        user.last_name = request.data['last_name']
        user.last_login = timezone.now()
        user.save()

        if settings.SEND_VERIFICATION_MAIN_ON_SIGNUP:
            tasks.send_verification_mail.delay(user.id)

        token, ok = Token.objects.get_or_create(user=user)

        user_serializer = UserSerializer(user)

        return Response(responses.generate_response(
            success=True,
            msg=USER_REGISTRATION_SUCCESSFUL_1100['message'],
            payload={
                'user': user_serializer.data,
                'token': token.key
            }),
            status=status.HTTP_201_CREATED)


class UserLogin(APIView):

    def post(self, request):
        """
            User login API

            Request sample for User login request

                    {
                            "email" : string,
                            "password": string
                    }


            ** Success


                {
                    "success": true,
                    "message": "User login successful",
                    "payload": {
                        "user": {
                            "id": 5,
                            "first_name": "Hiren",
                            "last_name": "Patel",
                            "email": "hiren4@yopmail.com",
                            "username": null,
                            "is_active": true,
                            "is_email_verified": false,
                            "created": "2018-07-02T06:54:08.802778Z",
                            "last_modified": "2018-07-02T06:54:08.903597Z",
                            "last_login": "2018-07-02T06:54:08.902997Z",
                            "user_role": null
                        },
                        "token": "3a849e37812c763df5726248cf3d5d8063a8a46f"
                    }
                }
        """

        serializer = UserLoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                responses.generate_failure_response(custom_codes.BAD_REQUEST_400,
                                                    payload=serializer.errors), status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=request.data['email'])
            if user.check_password(request.data['password']):
                token = Token.objects.get(user_id=user.id)
                user_serializer = UserSerializer(user)

                return Response(responses.generate_response(
                    success=True,
                    msg=USER_LOGIN_SUCCESSFUL_1101['message'],
                    payload={
                        'user': user_serializer.data,
                        'token': token.key
                    }),
                    status=status.HTTP_200_OK)
            else:
                return Response(
                    responses.generate_failure_response(custom_codes.INVALID_EMAIL_OR_PASSWORD_1003,
                                                        payload={}), status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response(
                responses.generate_failure_response(custom_codes.INVALID_EMAIL_OR_PASSWORD_1003,
                                                    payload={}), status=status.HTTP_400_BAD_REQUEST)


class UserOAuth(APIView):

    def post(self, request):
        """
            * API to store and authenticate user using OAuth cred


            * Sample request


                {
                    "access_token": "adsfdf gfgfagfg fagdf dsfd sfdasfds fdasfds fds",
                    "long_lived_access_token": string or undefined or null,
                    "email": "hirenpatel8495@gmail.com",
                    "oauth_user_id": "23424343432_234324324",
                    "oauth_provider_id": 1,
                    "token_expiration_time": "2019-05-30 11:49:28+00:00"
                }

        """
        # Validate request
        serializer = UserOAuthRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                responses.generate_failure_response(custom_codes.BAD_REQUEST_400,
                                                    payload=serializer.errors), status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email=request.data['email']).exists():
            is_new_user = False
        else:
            is_new_user = True

        strategy = load_strategy(request=request)
        if request.data['oauth_provider'] == 1:
            backend = 'facebook'
        elif request.data['oauth_provider'] == 2:
            backend = 'google-oauth2'
        elif request.data['oauth_provider'] == 3:
            backend = 'twitter'
        else:
            backend = 'linkedin'

        try:
            backend = load_backend(strategy, backend, reverse(NAMESPACE + ":complete", args=(backend,)))
        except MissingBackend:
            msg = 'Invalid token header. Invalid backend.'
            # raise exceptions.AuthenticationFailed(msg)
            return Response(
                responses.generate_failure_response(custom_codes.BAD_REQUEST_400,
                                                    payload={'msg': msg}), status=status.HTTP_400_BAD_REQUEST)

        try:
            user = backend.do_auth(access_token=request.data['access_token'])
        except requests.HTTPError as e:
            msg = e.response.text
            # raise exceptions.AuthenticationFailed(msg)
            return Response(
                responses.generate_failure_response(custom_codes.BAD_REQUEST_400,
                                                    payload={'msg': msg}), status=status.HTTP_400_BAD_REQUEST)
        except ValueError as e:
            msg = 'Bad request'
            # raise exceptions.AuthenticationFailed(msg)
            return Response(
                responses.generate_failure_response(custom_codes.BAD_REQUEST_400,
                                                    payload={'msg': msg}), status=status.HTTP_400_BAD_REQUEST)

        if not user:
            msg = 'Bad credentials.'
            # raise exceptions.AuthenticationFailed(msg)
            return Response(
                responses.generate_failure_response(custom_codes.BAD_REQUEST_400,
                                                    payload={'msg': msg}), status=status.HTTP_400_BAD_REQUEST)

        if is_new_user and settings.SEND_VERIFICATION_MAIN_ON_SIGNUP:
            tasks.send_verification_mail.delay(user.id)

        token, created = Token.objects.get_or_create(user=user)

        oauth_user_detail = {
            'access_token': request.data['access_token'],
            'long_lived_access_token': request.data['access_token'],
            'oauth_user_id': request.data['oauth_user'],
            'email': request.data['email'],
            'oauth_provider': request.data['oauth_provider'],
            'user': user.id
        }

        existing_oauth_user = OAuthUsers.objects.filter(oauth_user=request.data['oauth_user'], oauth_provider=request.data['oauth_provider'])

        if existing_oauth_user.exists():
            oauth_instance = existing_oauth_user[0]
            serializer = UserOAuthSerializer(data=oauth_user_detail, instance=oauth_instance)
        else:
            serializer = UserOAuthSerializer(data=oauth_user_detail)

        if serializer.is_valid():
            serializer.save()
        else:
            return Response(
                responses.generate_failure_response(custom_codes.BAD_REQUEST_400,
                                                    payload=serializer.errors), status=status.HTTP_400_BAD_REQUEST)

        # save oauth data
        # serializer.save()

        return Response({
            'message': 'User registration successful',
            'payload': {
                'user_id': user.id,
                'token': token.key
            }
        }, status=status.HTTP_201_CREATED)


class UserEmailVerification(APIView):
    permission_classes = (IsAuthenticated, )

    def get(self, request, user_id, verification_key):
        """
        UserEmailVerification API

        Invalid token

                {
                        "success": false,
                        "message": "Invalid token.",
                        "payload": {},
                        "error_code": 401
                }
                HTTP status code 401:- Unauthorized

        You do not have permission to perform this action.(Token's user_id and request user_id not match)

            {
                    "payload": {},
                    "error_code": 403,
                    "message": "You do not have permission to perform this action.",
                    "success": false
            }
            HTTP status code 403:- Forbidden

        User does not exists

            {
                    "success" : false,
                    "message" : "User does not exists"
                    "error_code" : 7006
                    "payload" : {}

            }
            HTTP status code 400:- BAD REQUEST

        Invalid email verification key

            {
                    "success" : false,
                    "message" : "Invalid email verification key"
                    "error_code" : 1005,
                    "payload" : {}

            }
            HTTP status code 400:- BAD REQUEST

        Email verification key expired

            {
                    "success" : false,
                    "message" : "Email verification key expired"
                    "error_code" : 1004,
                    "payload" : {}

            }
            HTTP status code 400:- BAD REQUEST

        Pending email verification not found for this user

            {
                    "success" : false,
                    "message" : "Pending email verification not found for this user"
                    "error_code" : 1006,
                    "payload" : {}

            }
            HTTP status code 400:- BAD REQUEST

        Email verified successfully

            {
                    "success" : true,
                    "message" : "Email verified successfully"
                    "payload" : {
                        "user_id": integer
                    }

            }
            HTTP status code 200:- OK



        """
        user_verification = UserVerification.objects.filter(user_id=user_id)
        if request.user.id != int(user_id):
            return Response(
                responses.generate_failure_response(custom_codes.NOT_ALLOWED_TO_PERFORM_THIS_ACTION_401,
                                                    payload={}),
                status=status.HTTP_401_UNAUTHORIZED)
        if user_verification.exists():
            user_verification = user_verification[0]
            if user_verification.key_expires < timezone.now():
                return Response(
                    responses.generate_failure_response(custom_codes.EMAIL_VERIFICATION_KEY_EXPIRED_1004,
                                                        payload={}),
                    status=status.HTTP_400_BAD_REQUEST)
            else:
                if user_verification.verification_key == verification_key:
                    user = request.user
                    # removed use of is_email_verified flag
                    # user.is_email_verified = True

                    # change status of email in the email_status table
                    user.is_email_verified = True
                    user.save()

                    payload = {"user_id": user.id}
                    return Response(
                        responses.generate_success_response(custom_codes.EMAIL_VERIFIED_SUCCESSFULLY_1102,
                                                              payload=payload),
                        status=status.HTTP_200_OK
                    )
                else:
                    return Response(
                        responses.generate_failure_response(custom_codes.INVALID_EMAIL_VERIFICATION_KEY_1005,
                                                              payload={}),
                        status=status.HTTP_400_BAD_REQUEST)

        else:
            return Response(responses.generate_failure_response(
                custom_codes.PENDING_EMAIL_VERIFICATION_NOT_FOUND_FOR_THIS_USER_1006, payload={}),
                status=status.HTTP_400_BAD_REQUEST)


class UserPasswordResetView(APIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, user_id):
        """

        * API endpoint to request password reset link

        """
        pass

    def post(self, request, user_id, password_reset_key):
        pass


class UserPasswordResetRequest(APIView):

    def post(self, request, **kwargs):
        """
            **Password Reset**
            to reset user password.

            ### POST

            Send mail to the user on specified email address with the link to
            reset password.

            * Requires only the `email` address.

            * Possible HTTP status codes and JSON response:

                * `HTTP status code 400` - If user with specified email is not found.

                        {
                                "success" : false,
                                "message" : "User with specified email does not exist"
                                "error_code" : 1008,
                                "payload" : {}

                        }

                * `HTTP_400_BAD_REQUEST` - If email is not specified.


                        {
                                "success" : false,
                                "message" : "Email is required for password reset request"
                                "error_code" : 1007,
                                "payload" : {}

                        }

                * `HTTP_200_OK` - When Password Reset Link is successfully sent.

                        {
                                "success" : true,
                                "message" : "Password reset link sent successfully"
                                "payload" : {}

                        }
        """
        if 'email' not in request.data:
            return Response(responses.generate_failure_response(
                custom_codes.EMAIL_IS_REQUIRED_FOR_PASSWORD_RESET_REQUEST_1007, payload={}),
                status=status.HTTP_400_BAD_REQUEST)
        email = request.data['email']
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(responses.generate_failure_response(
                custom_codes.USER_WITH_GIVEN_EMAIL_DOEST_NOT_EXISTS_1008, payload={}),
                status=status.HTTP_400_BAD_REQUEST)

        key = create_reset_password_key(user)
        tasks.send_reset_password_mail.delay(user.id, key)
        return Response(
            responses.generate_success_response(custom_codes.PASSWORD_RESET_LINK_SENT_SUCCESSFULLY_1103,
                                                payload={}),
            status=status.HTTP_200_OK
        )


class UserPasswordResetStatus(APIView):

    def get(self, request, user_id, key):
        """
        ** User Password reset key verfication **

        ### Success

            {
                "success": true,
                "message": "Password reset link is valid",
                "payload": {
                    "is_valid": true
                }
            }

        ### Failure

            {
                "success": false,
                "message": "Password reset request not found",
                "payload": {},
                "error_code": 1009
            }


            * If link is invalid or expired

            {
                "success": false,
                "message": "Password reset link expired",
                "payload": {},
                "error_code": 1010
            }


        """
        try:
            user_reset_password = UserResetPassword.objects.get(user_id=user_id)
        except UserResetPassword.DoesNotExist:
            return Response(responses.generate_failure_response(
                custom_codes.PASSWORD_RESET_REQUEST_NOT_FOUND_1009, payload={}),
                status=status.HTTP_400_BAD_REQUEST)

        if user_reset_password.key_expires < timezone.now():
            return Response(responses.generate_failure_response(
                custom_codes.PASSWORD_RESET_LINK_EXPIRED_1010, payload={}),
                status=status.HTTP_400_BAD_REQUEST)
        else:
            if user_reset_password.key == key:
                return Response(
                    responses.generate_success_response(custom_codes.PASSWORD_RESET_KEY_IS_VALID_1104,
                                                        payload={'is_valid': True}),
                    status=status.HTTP_200_OK
                )
            else:
                return Response(responses.generate_failure_response(
                    custom_codes.PASSWORD_RESET_LINK_EXPIRED_1010, payload={}),
                    status=status.HTTP_400_BAD_REQUEST)


class UserUpdatePassword(APIView):

    def put(self, request, user_id):
        """
        ** User new password set **

        ### Request

            {
                "new_password": string,
                "code": string
            }

        ### Success

            {
                "message": "Password changed successfully !"
            }

        ### Failure

            {
                "success": false,
                "message": "Password reset request not found",
                "payload": {},
                "error_code": 1009
            }

            * If link is invalid or expired

            {
                "success": false,
                "message": "Password reset link expired",
                "payload": {},
                "error_code": 1010
            }


        """
        if 'key' not in request.data:
            return Response(responses.generate_failure_response(
                custom_codes.KEY_IS_REQUIRED_TO_UPDATE_PASSWORD_1011, payload={}),
                status=status.HTTP_400_BAD_REQUEST)
        key = request.data['key']

        if 'new_password' not in request.data:
            return Response(responses.generate_failure_response(
                custom_codes.NEW_PASSWORD_IS_REQUIRED_TO_UPDATE_PASSWORD_1012, payload={}),
                status=status.HTTP_400_BAD_REQUEST)
        new_password = request.data['new_password']

        try:
            user_reset_password = UserResetPassword.objects.get(user_id=user_id)
        except UserResetPassword.DoesNotExist:
            return Response(responses.generate_failure_response(
                custom_codes.PASSWORD_RESET_REQUEST_NOT_FOUND_1009, payload={}),
                status=status.HTTP_400_BAD_REQUEST)

        if user_reset_password.key_expires < timezone.now():
            return Response(responses.generate_failure_response(
                custom_codes.PASSWORD_RESET_LINK_EXPIRED_1010, payload={}),
                status=status.HTTP_400_BAD_REQUEST)
        else:
            if user_reset_password.key == key:
                user = User.objects.get(id=user_id)
                user.set_password(new_password)
                user.save()
                return Response({"message": "Password changed successfully !"}, status=status.HTTP_200_OK)

            else:
                return Response(responses.generate_failure_response(
                    custom_codes.PASSWORD_RESET_LINK_EXPIRED_1010, payload={}),
                    status=status.HTTP_400_BAD_REQUEST)