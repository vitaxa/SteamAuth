package com.vitaxa.steamauth.model;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import com.vitaxa.steamauth.UserLogin;

public final class LoginResponse {
    @SerializedName("success")
    private boolean success;

    @SerializedName("login_complete")
    private boolean loginComplete;

    @SerializedName("oauth")
    private String oAuthDataString;

    private OAuth oAuthData;

    @SerializedName("captcha_needed")
    private boolean captchaNeeded;

    @SerializedName("captcha_gid")
    private String captchaGID;

    @SerializedName("emailsteamid")
    private long emailSteamID;

    @SerializedName("emailauth_needed")
    private boolean emailAuthNeeded;

    @SerializedName("requires_twofactor")
    private boolean twoFactorNeeded;

    @SerializedName("message")
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
        return oAuthDataString != null ? new Gson().fromJson(oAuthDataString, OAuth.class) : null;
    }

    public final class OAuth {
        @SerializedName("steamid")
        private long steamID;

        @SerializedName("oauth_token")
        private String oAuthToken;

        @SerializedName("wgtoken")
        private String steamLogin;

        @SerializedName("wgtoken_secure")
        private String steamLoginSecure;

        @SerializedName("webcookie")
        private String webcookie;

        public long getSteamID() {
            return steamID;
        }

        public String getoAuthToken() {
            return oAuthToken;
        }

        public String getSteamLogin() {
            return steamLogin;
        }

        public String getSteamLoginSecure() {
            return steamLoginSecure;
        }

        public String getWebcookie() {
            return webcookie;
        }
    }
}
