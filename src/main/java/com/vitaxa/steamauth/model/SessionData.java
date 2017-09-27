package com.vitaxa.steamauth.model;

import org.apache.http.client.CookieStore;
import org.apache.http.impl.cookie.BasicClientCookie;

import java.util.ArrayList;
import java.util.List;

public class SessionData {
    private String sessionID;

    private String steamLogin;

    private String steamLoginSecure;

    private String webCookie;

    private String oAuthToken;

    private long steamID;

    public void addCookies(CookieStore cookieStore) {
        List<CustomCookie> cookies = new ArrayList<>();

        cookies.add(new CustomCookie("mobileClientVersion", "0 (2.1.3)"));
        cookies.add(new CustomCookie("mobileClient", "android"));
        cookies.add(new CustomCookie("steamid", String.valueOf(steamID)));
        cookies.add(new CustomCookie("steamLogin", steamLogin));
        cookies.add(new CustomCookie("steamLoginSecure", steamLoginSecure, true));
        cookies.add(new CustomCookie("Steam_Language", ""));
        cookies.add(new CustomCookie("sessionid", sessionID));

        createCookies(cookieStore, cookies);
    }

    public String getSessionID() {
        return sessionID;
    }

    public void setSessionID(String sessionID) {
        this.sessionID = sessionID;
    }

    public String getSteamLogin() {
        return steamLogin;
    }

    public void setSteamLogin(String steamLogin) {
        this.steamLogin = steamLogin;
    }

    public String getSteamLoginSecure() {
        return steamLoginSecure;
    }

    public void setSteamLoginSecure(String steamLoginSecure) {
        this.steamLoginSecure = steamLoginSecure;
    }

    public String getWebCookie() {
        return webCookie;
    }

    public void setWebCookie(String webCookie) {
        this.webCookie = webCookie;
    }

    public String getOAuthToken() {
        return oAuthToken;
    }

    public void setOAuthToken(String OAuthToken) {
        this.oAuthToken = OAuthToken;
    }

    public long getSteamID() {
        return steamID;
    }

    public void setSteamID(long steamID) {
        this.steamID = steamID;
    }

    private void createCookies(CookieStore cookieStore, List<CustomCookie> cookies) {
        cookies.forEach(cookie -> {
            BasicClientCookie clientCookie = new BasicClientCookie(cookie.name, cookie.value);
            clientCookie.setDomain(".steamcommunity.com");
            clientCookie.setPath("/");

            if (cookie.secure)
                clientCookie.setSecure(true);

            // Add cookie to cookie store
            cookieStore.addCookie(clientCookie);
        });
    }

    private final class CustomCookie {
        private final String name;
        private final String value;
        private final boolean secure;

        public CustomCookie(String name, String value) {
            this.name = name;
            this.value = value;
            this.secure = false;
        }

        public CustomCookie(String name, String value, boolean secure) {
            this.name = name;
            this.value = value;
            this.secure = secure;
        }
    }
}
