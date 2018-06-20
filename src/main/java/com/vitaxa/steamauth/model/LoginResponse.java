package com.vitaxa.steamauth.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.vitaxa.steamauth.helper.Json;

public final class LoginResponse {
    @JsonProperty
    private boolean success;

    @JsonProperty("login_complete")
    private boolean loginComplete;

    @JsonProperty("oauth")
    private String oAuthDataString;

    private OAuth oAuthData;

    @JsonProperty("captcha_needed")
    private boolean captchaNeeded;

    @JsonProperty("captcha_gid")
    private String captchaGID;

    @JsonProperty("emailsteamid")
    private long emailSteamID;

    @JsonProperty("emailauth_needed")
    private boolean emailAuthNeeded;

    @JsonProperty("requires_twofactor")
    private boolean twoFactorNeeded;

    @JsonProperty("message")
    private String message;

    public boolean isSuccess() {
        return success;
    }

    public boolean isLoginComplete() {
        return loginComplete;
    }

    public String getoAuthDataString() {
        return oAuthDataString;
    }

    public boolean isCaptchaNeeded() {
        return captchaNeeded;
    }

    public String getCaptchaGID() {
        return captchaGID;
    }

    public long getEmailSteamID() {
        return emailSteamID;
    }

    public boolean isEmailAuthNeeded() {
        return emailAuthNeeded;
    }

    public boolean isTwoFactorNeeded() {
        return twoFactorNeeded;
    }

    public String getMessage() {
        return message;
    }

    public OAuth getoAuthData() {
        return oAuthDataString != null ? Json.getInstance().fromJson(oAuthDataString, OAuth.class) : null;
    }
}
