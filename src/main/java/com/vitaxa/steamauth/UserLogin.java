package com.vitaxa.steamauth;

import com.vitaxa.steamauth.helper.IOHelper;
import com.vitaxa.steamauth.helper.Json;
import com.vitaxa.steamauth.http.HttpMethod;
import com.vitaxa.steamauth.http.HttpParameters;
import com.vitaxa.steamauth.model.*;
import org.apache.http.cookie.Cookie;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class UserLogin {

    private final static Logger LOG = LoggerFactory.getLogger(UserLogin.class);

    private final String username;
    private final String password;
    private final Map<String, String> cookies;
    private long steamID;
    private boolean requiresCaptcha;
    private String captchaGID = null;
    private String captchaText = null;
    private boolean requiresEmail;
    private String emailDomain = null;
    private String emailCode = null;
    private boolean requires2FA;
    private String twoFactorCode = null;
    private SessionData session = null;
    private boolean loggedIn = false;

    public UserLogin(String username, String password) {
        this.username = username;
        this.password = password;
        this.cookies = new HashMap<>();
    }

    public LoginResult doLogin() {
        Map<String, String> postData = new HashMap<>();
        String response = "";

        if (cookies.size() == 0) {
            //Generate a SessionID
            cookies.put("mobileClientVersion", "0 (2.1.3)");
            cookies.put("mobileClient", "android");
            cookies.put("Steam_Language", "english");
            SteamWeb.addCookies(cookies);

            Map<String, String> headers = new HashMap<>();
            headers.put("X-Requested-With", "com.valvesoftware.android.steam.community");

            SteamWeb.mobileLoginRequest("https://steamcommunity.com/login?oauth_client_id=DE45CD61&oauth_scope=read_profile%20write_profile%20read_client%20write_client",
                    new HttpParameters(HttpMethod.GET), headers);
        }

        postData.put("donotcache", String.valueOf(TimeAligner.getSteamTime() * 1000));
        postData.put("username", username);
        response = SteamWeb.mobileLoginRequest(APIEndpoints.COMMUNITY_BASE + "/login/getrsakey",
                new HttpParameters(postData, HttpMethod.POST));

        if (response == null || response.contains("<BODY>\nAn error occurred while processing your request."))
            return LoginResult.GENERAL_FAILURE;

        RSAResponse rsaResponse = Json.getInstance().fromJson(response, RSAResponse.class);

        if (!rsaResponse.isSuccess())
            return LoginResult.BAD_RSA;

        try {
            Thread.sleep(350); //Sleep for a bit to give Steam a chance to catch up??
        } catch (InterruptedException e) {
            LOG.error("User login was interrupted", e);
        }

        SecureRandom secureRandom = new SecureRandom();
        byte[] encryptedPasswordBytes;
        byte[] passwordBytes = IOHelper.encode(password);
        String encryptedPassword;

        try {
            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(new BigInteger(rsaResponse.getModulus(), 16),
                    new BigInteger(rsaResponse.getExponent(), 16));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKey RSAkey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, RSAkey);

            encryptedPassword = Base64.getEncoder().encodeToString(cipher.doFinal(passwordBytes));
        } catch (Exception e) {
            LOG.error("Could't encrypt password", e);
            return LoginResult.BAD_RSA;
        }

        postData.clear();

        postData.put("donotcache", String.valueOf(TimeAligner.getSteamTime() * 1000));

        postData.put("password", encryptedPassword);
        postData.put("username", username);
        postData.put("twofactorcode", twoFactorCode != null ? twoFactorCode : "");

        postData.put("emailauth", requiresEmail ? emailCode : "");
        postData.put("loginfriendlyname", "");
        postData.put("captchagid", requiresCaptcha ? captchaGID : "-1");
        postData.put("captcha_text", requiresCaptcha ? captchaText : "");
        postData.put("emailsteamid", (requires2FA || requiresEmail) ? String.valueOf(steamID) : "");

        postData.put("rsatimestamp", rsaResponse.getTimestamp());
        postData.put("remember_login", "true");
        postData.put("oauth_client_id", "DE45CD61");
        postData.put("oauth_scope", "read_profile write_profile read_client write_client");

        response = SteamWeb.mobileLoginRequest(APIEndpoints.COMMUNITY_BASE + "/login/dologin", new HttpParameters(postData, HttpMethod.POST));

        LoginResponse loginResponse = Json.getInstance().fromJson(response, LoginResponse.class);

        if (loginResponse == null) return LoginResult.GENERAL_FAILURE;

        if (loginResponse.getMessage() != null) {
            if (loginResponse.getMessage().contains("There have been too many login failures")) {
                return LoginResult.TOO_MANY_FAILED_LOGINS;
            }
            if (loginResponse.getMessage().contains("Incorrect login")) {
                return LoginResult.BAD_CREDENTIALS;
            }
        }

        if (loginResponse.isCaptchaNeeded()) {
            requiresCaptcha = true;
            captchaGID = loginResponse.getCaptchaGID();
            return LoginResult.NEED_CAPTCHA;
        }

        if (loginResponse.isEmailAuthNeeded()) {
            requiresEmail = true;
            steamID = loginResponse.getEmailSteamID();
            return LoginResult.NEED_EMAIL;
        }

        if (loginResponse.isTwoFactorNeeded() && !loginResponse.isSuccess()) {
            requires2FA = true;
            return LoginResult.NEED_2FA;
        }

        OAuth oAuthData = loginResponse.getoAuthData();
        if (oAuthData == null || oAuthData.getoAuthToken() == null || oAuthData.getoAuthToken().length() == 0) {
            return LoginResult.GENERAL_FAILURE;
        }

        if (!loginResponse.isLoginComplete()) {
            return LoginResult.BAD_CREDENTIALS;
        } else {
            List<Cookie> readableCookies = SteamWeb.getCookies();

            SessionData session = new SessionData();
            session.setOAuthToken(oAuthData.getoAuthToken());
            session.setSteamID(oAuthData.getSteamID());
            session.setSteamLogin(session.getSteamID() + "%7C%7C" + oAuthData.getSteamLogin());
            session.setSteamLoginSecure(session.getSteamID() + "%7C%7C" + oAuthData.getSteamLoginSecure());
            session.setWebCookie(oAuthData.getWebcookie());

            for (Cookie cookie : readableCookies) {
                if (cookie.getName().equalsIgnoreCase("sessionid"))
                    session.setSessionID(cookie.getValue());
            }

            this.session = session;
            this.loggedIn = true;

            return LoginResult.LOGIN_OKAY;
        }
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public long getSteamID() {
        return steamID;
    }

    public void setSteamID(long steamID) {
        this.steamID = steamID;
    }

    public boolean isRequiresCaptcha() {
        return requiresCaptcha;
    }

    public void setRequiresCaptcha(boolean requiresCaptcha) {
        this.requiresCaptcha = requiresCaptcha;
    }

    public String getCaptchaGID() {
        return captchaGID;
    }

    public void setCaptchaGID(String captchaGID) {
        this.captchaGID = captchaGID;
    }

    public String getCaptchaText() {
        return captchaText;
    }

    public void setCaptchaText(String captchaText) {
        this.captchaText = captchaText;
    }

    public boolean isRequiresEmail() {
        return requiresEmail;
    }

    public void setRequiresEmail(boolean requiresEmail) {
        this.requiresEmail = requiresEmail;
    }

    public boolean isRequires2FA() {
        return requires2FA;
    }

    public void setRequires2FA(boolean requires2FA) {
        this.requires2FA = requires2FA;
    }

    public String getTwoFactorCode() {
        return twoFactorCode;
    }

    public void setTwoFactorCode(String twoFactorCode) {
        this.twoFactorCode = twoFactorCode;
    }

    public boolean isLoggedIn() {
        return loggedIn;
    }

    public void setLoggedIn(boolean loggedIn) {
        this.loggedIn = loggedIn;
    }

    public String getEmailDomain() {
        return emailDomain;
    }

    public void setEmailDomain(String emailDomain) {
        this.emailDomain = emailDomain;
    }

    public String getEmailCode() {
        return emailCode;
    }

    public void setEmailCode(String emailCode) {
        this.emailCode = emailCode;
    }

    public SessionData getSession() {
        return session;
    }

    public void setSession(SessionData session) {
        this.session = session;
    }
}
