package com.vitaxa.steamauth;

import com.google.gson.annotations.SerializedName;

public class SteamResponse<T> {
    @SerializedName("response")
    public T response;

    public T getResponse() {
        return response;
    }

    public void setResponse(T response) {
        this.response = response;
    }
}
