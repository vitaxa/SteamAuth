package com.vitaxa.steamauth.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class TimeQuery {
    @JsonProperty("server_time")
    public long serverTime;
}
