package com.vitaxa.steamauth.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class OAuth {
    @JsonProperty("steamid")
    private long steamID;

    @JsonProperty("oauth_token")
    private String oAuthToken;

    @JsonProperty("wgtoken")
    private String steamLogin;

    @JsonProperty("wgtoken_secure")
    private String steamLoginSecure;

    @JsonProperty("webcookie")
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
