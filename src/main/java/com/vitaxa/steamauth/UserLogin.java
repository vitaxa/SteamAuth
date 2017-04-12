package com.vitaxa.steamauth;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import com.vitaxa.steamauth.helper.CommonHelper;
import com.vitaxa.steamauth.helper.IOHelper;
import com.vitaxa.steamauth.http.HttpMethod;
import com.vitaxa.steamauth.http.HttpParameters;
import com.vitaxa.steamauth.model.LoginResponse;
import com.vitaxa.steamauth.model.LoginResult;
import com.vitaxa.steamauth.model.SessionData;
import org.apache.http.cookie.Cookie;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class UserLogin {
    public final String username;
    public final String password;
    public long steamID;

    public boolean requiresCaptcha;
    public String captchaGID = null;
    public String captchaText = null;

    public boolean requiresEmail;
    public String emailDomain = null;
    public String emailCode = null;

    public boolean requires2FA;
    public String twoFactorCode = null;

    public SessionData session = null;
    public boolean loggedIn = false;

    private final Map<String, String> cookies;

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

        postData.put("username", username);
        response = SteamWeb.mobileLoginRequest(APIEndpoints.COMMUNITY_BASE + "/login/getrsakey",
                new HttpParameters(postData, HttpMethod.POST));

        if (response == null || response.contains("<BODY>\nAn error occurred while processing your request."))
            return LoginResult.GENERAL_FAILURE;

        RSAResponse rsaResponse = new Gson().fromJson(response, RSAResponse.class);

        if (!rsaResponse.success)
            return LoginResult.BAD_RSA;

        SecureRandom secureRandom = new SecureRandom();
        byte[] encryptedPasswordBytes;
        byte[] passwordBytes = IOHelper.encode(password);
        String encryptedPassword;

        try {
            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(new BigInteger(rsaResponse.modulus, 16),
                    new BigInteger(rsaResponse.exponent, 16));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKey RSAkey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, RSAkey);

            encryptedPassword = Base64.getEncoder().encodeToString(cipher.doFinal(passwordBytes));
        } catch (Exception e) {
            e.printStackTrace();
            return LoginResult.BAD_RSA;
        }

        postData.clear();
        postData.put("username", username);
        postData.put("password", encryptedPassword);

        postData.put("twofactorcode", twoFactorCode != null ? twoFactorCode : "");

        postData.put("captchagid", requiresCaptcha ? captchaGID : "-1");
        postData.put("captcha_text", requiresCaptcha ? captchaText : "");

        postData.put("emailsteamid", (requires2FA || requiresEmail) ? String.valueOf(steamID) : "");
        postData.put("emailauth", requiresEmail ? emailCode : "");

        postData.put("rsatimestamp", rsaResponse.timestamp);
        postData.put("remember_login", "false");
        postData.put("oauth_client_id", "DE45CD61");
        postData.put("oauth_scope", "read_profile write_profile read_client write_client");
        postData.put("loginfriendlyname", "#login_emailauth_friendlyname_mobile");
        postData.put("donotcache", String.valueOf(CommonHelper.getUnixTimeStamp()));

        response = SteamWeb.mobileLoginRequest(APIEndpoints.COMMUNITY_BASE + "/login/dologin", new HttpParameters(postData, HttpMethod.POST));

        LoginResponse loginResponse = new Gson().fromJson(response, LoginResponse.class);

        if (loginResponse.getMessage() != null && loginResponse.getMessage().contains("The account name or password that you have entered is incorrect.")) {
            return LoginResult.BAD_CREDENTIALS;
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

        if (loginResponse.getMessage() != null && loginResponse.getMessage().contains("too many login failures")) {
            return LoginResult.TOO_MANY_FAILED_LOGINS;
        }

        LoginResponse.OAuth oAuthData = loginResponse.getoAuthData();
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

    private final class RSAResponse {
        @SerializedName("success")
        public boolean success;

        @SerializedName("publickey_exp")
        public String exponent;

        @SerializedName("publickey_mod")
        public String modulus;

        @SerializedName("timestamp")
        public String timestamp;

        @SerializedName("steamid")
        public long steamID;
    }
}
