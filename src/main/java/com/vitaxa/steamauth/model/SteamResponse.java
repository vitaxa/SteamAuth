package com.vitaxa.steamauth.model;

import com.fasterxml.jackson.annotation.JsonProperty;


public class SteamResponse<T> {
    @JsonProperty("response")
    private T response;

    public T getResponse() {
        return response;
    }
}
