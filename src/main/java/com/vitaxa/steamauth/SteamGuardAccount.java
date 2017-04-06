package com.vitaxa.steamauth;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import com.google.gson.reflect.TypeToken;
import com.vitaxa.steamauth.crypto.HMACSHA1;
import com.vitaxa.steamauth.helper.IOHelper;
import com.vitaxa.steamauth.http.HttpMethod;
import com.vitaxa.steamauth.http.HttpParameters;
import jdk.nashorn.internal.runtime.regexp.joni.Regex;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.Type;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class SteamGuardAccount {
    @SerializedName("shared_secret")
    private String sharedSecret;

    @SerializedName("serial_number")
    private String serialNumber;

    @SerializedName("revocation_code")
    private String revocationCode;

    @SerializedName("uri")
    private String URI;

    @SerializedName("server_time")
    private long serverTime;

    @SerializedName("account_name")
    private String accountName;

    @SerializedName("token_gid")
    private String tokenGID;

    @SerializedName("identity_secret")
    private String identitySecret;

    @SerializedName("secret_1")
    private String secret1;

    @SerializedName("status")
    private int status;

    @SerializedName("device_id")
    private String deviceID;

    //Set to true if the authenticator has actually been applied to the account.
    @SerializedName("fully_enrolled")
    public boolean fullyEnrolled;

    private SessionData session;

    private static byte[] steamGuardCodeTranslations = new byte[] { 50, 51, 52, 53, 54, 55, 56, 57, 66, 67, 68, 70, 71, 72, 74, 75, 77, 78, 80, 81, 82, 84, 86, 87, 88, 89 };

    private Pattern confIDRegex = Pattern.compile("data-confid=\"(\\d+)\"");
    private Pattern confKeyRegex = Pattern.compile("data-key=\"(\\d+)\"");
    private Pattern confDescRegex = Pattern.compile("<div>((Confirm|Trade with|Sell -) .+)</div>");

    public boolean acceptConfirmation(Confirmation conf) {
        return sendConfirmationAjax(conf, "allow");
    }

    public boolean denyConfirmation(Confirmation conf) {
        return sendConfirmationAjax(conf, "cancel");
    }

    public boolean deactivateAuthenticator(int scheme) {
        Map<String, String> postData = new HashMap<>(4);
        postData.put("steamid", String.valueOf(session.getSteamID()));
        postData.put("steamguard_scheme", String.valueOf(scheme));
        postData.put("revocation_code", revocationCode);
        postData.put("access_token", session.getOAuthToken());

        try {
            String response = SteamWeb.mobileLoginRequest(APIEndpoints.STEAMAPI_BASE +
                    "/ITwoFactorService/RemoveAuthenticator/v0001", new HttpParameters(postData, HttpMethod.POST));

            Type responseType = new TypeToken<SteamResponse<RemoveAuthenticatorResponse>>(){}.getType();

            RemoveAuthenticatorResponse removeResponse = new Gson().fromJson(response, responseType);

            return !(removeResponse == null || !removeResponse.isSuccess());
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public Confirmation[] fetchConfirmations() throws WGTokenInvalidException {
        String url = generateConfirmationURL();

        String response = SteamWeb.fetch(url, new HttpParameters(HttpMethod.GET));

        if (response == null || !(confIDRegex.matcher(response).find() && confKeyRegex.matcher(response).find()
                && confDescRegex.matcher(response).find())) {
            if (response == null || !response.contains("<div>Nothing to confirm</div>")) {
                throw new WGTokenInvalidException("Nothing to confirm");
            }
            return new Confirmation[0];
        }

        // Trying to parse response
        Matcher confIDs = confIDRegex.matcher(response);
        Matcher confKeys = confKeyRegex.matcher(response);
        Matcher confDescs = confDescRegex.matcher(response);


        // TODO: Дописать
        /*
        List<Confirmation> ret = new ArrayList<>();
        for (int i = 0; i < confIDs.groupCount(); i++) {
            string confID = confIDs.group(1);
            string confKey = confKeys[i].Groups[1].Value;
            string confDesc = confDescs[i].Groups[1].Value;
            Confirmation conf = new Confirmation()
            {
                Description = confDesc,
                ID = confID,
                Key = confKey
            };
            ret.Add(conf);
        }
        */

        return new Confirmation[0];
    }

    public String generateSteamGuardCode() {
        return generateSteamGuardCodeForTime(TimeAligner.getSteamTime());
    }

    public String generateSteamGuardCodeForTime(long time) {
        if (sharedSecret == null || sharedSecret.length() == 0) return "";

        // Shared secret is our key
        String sharedSecretUnescaped = IOHelper.decode(Base64.getDecoder().decode(sharedSecret));

        byte[] sharedSecretArray = Base64.getDecoder().decode(sharedSecretUnescaped);
        byte[] timeArray = new byte[8];

        // Time for code
        time /= 30L;
        for (int i = 8; i > 0; i--) {
            timeArray[i - 1] = (byte)time;
            time >>= 8;
        }

        // Generate hmac
        byte[] codeArray = new byte[5];
        try {
            byte[] hashedData = HMACSHA1.calculate(timeArray, sharedSecretArray);

            // the last 4 bits of the hashedData say where the code starts
            // (e.g. if last 4 bit are 1100, we start at byte 12)
            byte b = (byte)(hashedData[19] & 0xF);

            int codePoint = (hashedData[b] & 0x7F) << 24 | (hashedData[b + 1] & 0xFF) << 16 | (hashedData[b + 2] & 0xFF) << 8 | (hashedData[b + 3] & 0xFF);

            for (int i = 0; i < 5; ++i) {
                codeArray[i] = steamGuardCodeTranslations[codePoint % steamGuardCodeTranslations.length];
                codePoint /= steamGuardCodeTranslations.length;
            }
        } catch (InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }
        return IOHelper.decode(codeArray);
    }

    public long getConfirmationTradeOfferID(Confirmation conf) {
        ConfirmationDetailsResponse confDetails = getConfirmationDetails(conf);
        if (confDetails == null || !confDetails.success) return -1;

        Pattern tradeOfferIDRegex = Pattern.compile("<div class=\"tradeoffer\" id=\"tradeofferid_(\\d+)\" >");
        if (!tradeOfferIDRegex.matcher(confDetails.html).find()) return -1;

        return Long.valueOf(tradeOfferIDRegex.matcher(confDetails.html).group(1));
    }

    public String generateConfirmationURL() {
        return generateConfirmationURL("conf");
    }

    public String generateConfirmationURL(String tag) {
        String endpoint = APIEndpoints.COMMUNITY_BASE + "/mobileconf/conf?";
        String queryString = generateConfirmationQueryParams(tag);

        return endpoint + queryString;
    }

    public String generateConfirmationQueryParams(String tag) {
        if (deviceID != null && !deviceID.isEmpty())
            throw new IllegalArgumentException("Device ID is not present");

        Map<String, String> queryParams = generateConfirmationQueryParamsAsNVC(tag);

        return "p=" + queryParams.get("p") + "&a=" + queryParams.get("a") + "&k=" + queryParams.get("k") + "&t="
                + queryParams.get("t") + "&m=android&tag=" + queryParams.get("tag");
    }

    public Map<String, String> generateConfirmationQueryParamsAsNVC(String tag) {
        if (deviceID != null && !deviceID.isEmpty())
            throw new IllegalArgumentException("Device ID is not present");

        long time = TimeAligner.getSteamTime();

        Map<String, String> ret = new HashMap<>();
        ret.put("p", deviceID);
        ret.put("a", String.valueOf(session.getSteamID()));
        ret.put("k", generateConfirmationHashForTime(time, tag));
        ret.put("t", String.valueOf(time));
        ret.put("m", "android");
        ret.put("tag", tag);

        return ret;
    }

    /**
     * Refreshes the Steam session. Necessary to perform confirmations if your session has expired or changed.
     */
    public boolean refreshSession() {
        String url = APIEndpoints.MOBILEAUTH_GETWGTOKEN;
        Map<String, String> data = new HashMap<>();
        data.put("access_token", session.getOAuthToken());

        String response = SteamWeb.fetch(url, new HttpParameters(data, HttpMethod.POST));

        if (response.isEmpty()) return false;

        Type responseType = new TypeToken<SteamResponse<RefreshSessionDataResponse>>(){}.getType();
        RefreshSessionDataResponse refreshResponse = new Gson().fromJson(response, responseType);

        if (refreshResponse.token == null) return false;

        String token = session.getSteamID() + "%7C%7C" + refreshResponse.token;
        String tokenSecure = session.getSteamID() + "%7C%7C" + refreshResponse.tokenSecure;

        session.setSteamLogin(token);
        session.setSteamLoginSecure(tokenSecure);

        return true;
    }

    private ConfirmationDetailsResponse getConfirmationDetails(Confirmation conf) {
        String url = APIEndpoints.COMMUNITY_BASE + "/mobileconf/details/" + conf.getId() + "?";
        String queryString = generateConfirmationQueryParams("details");
        url += queryString;

        String response = SteamWeb.fetch(url, new HttpParameters(HttpMethod.GET));
        if (response.isEmpty()) return null;

        ConfirmationDetailsResponse confResponse = new Gson().fromJson(response, ConfirmationDetailsResponse.class);
        if (confResponse == null) return null;

        return confResponse;
    }

    private boolean sendConfirmationAjax(Confirmation conf, String op) {
        String url = APIEndpoints.COMMUNITY_BASE + "/mobileconf/ajaxop";
        String queryString = "?op=" + op + "&";
        queryString += generateConfirmationQueryParams(op);
        queryString += "&cid=" + conf.getId() + "&ck=" + conf.getKey();
        url += queryString;

        String response = SteamWeb.fetch(url, new HttpParameters(HttpMethod.GET));
        if (response == null) return false;

        SendConfirmationResponse confResponse = new Gson().fromJson(response, SendConfirmationResponse.class);

        return confResponse.success;
    }

    private String generateConfirmationHashForTime(long time, String tag) {
        byte[] decode = Base64.getDecoder().decode(identitySecret);
        int n2 = 8;
        if (tag != null) {
            if (tag.length() > 32) {
                n2 = 8 + 32;
            } else {
                n2 = 8 + tag.length();
            }
        }
        byte[] array = new byte[n2];
        int n3 = 8;
        while (true) {
            int n4 = n3 - 1;
            if (n3 <= 0) {
                break;
            }
            array[n4] = (byte)time;
            time >>= 8;
            n3 = n4;
        }
        if (tag != null) {
            System.arraycopy(IOHelper.encode(tag), 0, array, 8, n2 - 8);
        }

        try {
            byte[] hashedData = HMACSHA1.calculate(array, decode);
            String encodedData = Base64.getEncoder().encodeToString(hashedData);

            return URLEncoder.encode(encodedData, "UTF-8");
        } catch (UnsupportedEncodingException | InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }
    }

    public int getStatus() {
        return status;
    }

    public SteamGuardAccount setStatus(int status) {
        this.status = status;
        return this;
    }

    public SessionData getSession() {
        return session;
    }

    public SteamGuardAccount setSession(SessionData session) {
        this.session = session;
        return this;
    }

    public String getSharedSecret() {
        return sharedSecret;
    }

    public SteamGuardAccount setSharedSecret(String sharedSecret) {
        this.sharedSecret = sharedSecret;
        return this;
    }

    public String getDeviceID() {
        return deviceID;
    }

    public SteamGuardAccount setDeviceID(String deviceID) {
        this.deviceID = deviceID;
        return this;
    }

    private class RefreshSessionDataResponse {
        @SerializedName("token")
        public String token;

        @SerializedName("token_secure")
        public String tokenSecure;
    }

    private class RemoveAuthenticatorResponse {
        @SerializedName("success")
        private boolean success;

        public boolean isSuccess() {
            return success;
        }
    }

    private class SendConfirmationResponse {
        public boolean success;
    }

    private class ConfirmationDetailsResponse {
        public boolean success;

        public String html;
    }
}
