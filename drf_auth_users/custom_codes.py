# message digest for drf_auth_users api responses

# others
ERR_CODE = "err_code"
SUCCESS_CODE = "success_code"
MSG = "message"

# general
INTERNAL_SERVER_ERROR_500 = {
    ERR_CODE: 500,
    MSG: "Something went wrong. Please try again after sometime."}
FORBIDDEN_403 = {
    ERR_CODE: 403,
    MSG: 'You do not have permission to perform this action.'}
BAD_REQUEST_400 = {
    ERR_CODE: 400,
    MSG: 'Bad request'
}
NOT_FOUND_404 = {
    ERR_CODE: 404,
    MSG: 'Requested resource does not exists'
}
NOT_ALLOWED_TO_PERFORM_THIS_ACTION_401 = {
    ERR_CODE: 401,
    MSG: 'You are not allowed to perform this action'
}

INTEGRITY_ERROR = {
    ERR_CODE: 1000,
    MSG: 'IntegrityError'
}

# Success codes range (1100 - 1200)

USER_REGISTRATION_SUCCESSFUL_1100 = {
    SUCCESS_CODE: 1100,
    MSG: 'User registration successful'
}

USER_LOGIN_SUCCESSFUL_1101 = {
    SUCCESS_CODE: 1101,
    MSG: 'User login successful'
}

EMAIL_VERIFIED_SUCCESSFULLY_1102 = {
    SUCCESS_CODE: 1102,
    MSG: 'Email verified successfully'
}

PASSWORD_RESET_LINK_SENT_SUCCESSFULLY_1103 = {
    SUCCESS_CODE: 1103,
    MSG: 'Password reset link sent successfully'
}

PASSWORD_RESET_KEY_IS_VALID_1104 = {
    SUCCESS_CODE: 1104,
    MSG: 'Password reset link is valid'
}

# custom Auth error codes range (1001 - 1100)

REQUIRED_FIELD_MISSING_1001 = {
    ERR_CODE: 1001,
    MSG: "required field(s) is/are missing"
}

ACCOUNT_ALREADY_EXISTS_1002 = {
    ERR_CODE: 1002,
    MSG: "Account with same email already exists"
}

INVALID_EMAIL_OR_PASSWORD_1003 = {
    ERR_CODE: 1003,
    MSG: 'Invalid email or password'
}

EMAIL_VERIFICATION_KEY_EXPIRED_1004 = {
    ERR_CODE: 1004,
    MSG: 'Email verification key expired'
}

INVALID_EMAIL_VERIFICATION_KEY_1005 = {
    ERR_CODE: 1005,
    MSG: 'Invalid email verification key'
}

PENDING_EMAIL_VERIFICATION_NOT_FOUND_FOR_THIS_USER_1006 = {
    ERR_CODE: 1006,
    MSG: 'Pending email verification not found for this user'
}

EMAIL_IS_REQUIRED_FOR_PASSWORD_RESET_REQUEST_1007 = {
    ERR_CODE: 1007,
    MSG: 'Email is required for password reset request'
}

USER_WITH_GIVEN_EMAIL_DOEST_NOT_EXISTS_1008 = {
    ERR_CODE: 1008,
    MSG: 'User with specified email does not exist'
}

PASSWORD_RESET_REQUEST_NOT_FOUND_1009 = {
    ERR_CODE: 1009,
    MSG: 'Password reset request not found'
}

PASSWORD_RESET_LINK_EXPIRED_1010 = {
    ERR_CODE: 1010,
    MSG: 'Password reset link expired'
}

KEY_IS_REQUIRED_TO_UPDATE_PASSWORD_1011 = {
    ERR_CODE: 1011,
    MSG: 'Key is required to update password'
}

NEW_PASSWORD_IS_REQUIRED_TO_UPDATE_PASSWORD_1012 = {
    ERR_CODE: 1012,
    MSG: "'new_password' is required to update password"
}

