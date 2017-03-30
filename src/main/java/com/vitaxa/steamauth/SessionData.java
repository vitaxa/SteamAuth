package com.vitaxa.steamauth;

public class SessionData {
    public String SessionID;

    public String SteamLogin;

    public String SteamLoginSecure;

    public String WebCookie;

    public String OAuthToken;

    public long SteamID;

    //public void addcookies();

    public String getSessionID() {
        return SessionID;
    }

    public void setSessionID(String sessionID) {
        SessionID = sessionID;
    }

    public String getSteamLogin() {
        return SteamLogin;
    }

    public void setSteamLogin(String steamLogin) {
        SteamLogin = steamLogin;
    }

    public String getSteamLoginSecure() {
        return SteamLoginSecure;
    }

    public void setSteamLoginSecure(String steamLoginSecure) {
        SteamLoginSecure = steamLoginSecure;
    }

    public String getWebCookie() {
        return WebCookie;
    }

    public void setWebCookie(String webCookie) {
        WebCookie = webCookie;
    }

    public String getOAuthToken() {
        return OAuthToken;
    }

    public void setOAuthToken(String OAuthToken) {
        this.OAuthToken = OAuthToken;
    }

    public long getSteamID() {
        return SteamID;
    }

    public void setSteamID(long steamID) {
        SteamID = steamID;
    }
}
