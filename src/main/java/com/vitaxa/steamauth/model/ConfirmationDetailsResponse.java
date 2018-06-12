package com.vitaxa.steamauth.model;

public class ConfirmationDetailsResponse {
    public boolean success;

    public String html;

    public boolean isSuccess() {
        return success;
    }

    public String getHtml() {
        return html;
    }
}
