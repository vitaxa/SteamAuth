package com.vitaxa.steamauth.model;

import com.google.gson.annotations.SerializedName;

public class SteamResponse<T> {
    @SerializedName("response")
    private T response;

    public T getResponse() {
        return response;
    }
}
