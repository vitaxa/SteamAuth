package com.vitaxa.steamauth.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class RefreshSessionDataResponse {
    @JsonProperty("token")
    public String token;

    @JsonProperty("token_secure")
    public String tokenSecure;

    public String getToken() {
        return token;
    }

    public String getTokenSecure() {
        return tokenSecure;
    }
}
