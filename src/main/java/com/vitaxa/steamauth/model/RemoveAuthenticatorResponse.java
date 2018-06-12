package com.vitaxa.steamauth.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class RemoveAuthenticatorResponse {
    @JsonProperty("success")
    private boolean success;

    public boolean isSuccess() {
        return success;
    }
}
