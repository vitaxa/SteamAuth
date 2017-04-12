package com.vitaxa.steamauth.model;

public enum LoginResult {
    LOGIN_OKAY,
    GENERAL_FAILURE,
    BAD_RSA,
    BAD_CREDENTIALS,
    NEED_CAPTCHA,
    NEED_2FA,
    NEED_EMAIL,
    TOO_MANY_FAILED_LOGINS
}
