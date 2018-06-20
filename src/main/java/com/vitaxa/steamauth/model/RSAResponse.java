package com.vitaxa.steamauth.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class RSAResponse {
    @JsonProperty("success")
    private boolean success;

    @JsonProperty("publickey_exp")
    private String exponent;

    @JsonProperty("publickey_mod")
    private String modulus;

    @JsonProperty("timestamp")
    private String timestamp;

    @JsonProperty("steamid")
    private long steamID;

    public boolean isSuccess() {
        return success;
    }

    public String getExponent() {
        return exponent;
    }

    public String getModulus() {
        return modulus;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public long getSteamID() {
        return steamID;
    }
}
