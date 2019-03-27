package com.vitaxa.steamauth;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.type.TypeReference;
import com.vitaxa.steamauth.crypto.HMACSHA1;
import com.vitaxa.steamauth.exception.WGTokenInvalidException;
import com.vitaxa.steamauth.helper.IOHelper;
import com.vitaxa.steamauth.helper.Json;
import com.vitaxa.steamauth.http.HttpMethod;
import com.vitaxa.steamauth.http.HttpParameters;
import com.vitaxa.steamauth.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class SteamGuardAccount {

    private final Logger LOG = LoggerFactory.getLogger(SteamGuardAccount.class);

    private static byte[] steamGuardCodeTranslations = new byte[]{50, 51, 52, 53, 54, 55, 56, 57, 66, 67, 68, 70, 71, 72, 74, 75, 77, 78, 80, 81, 82, 84, 86, 87, 88, 89};
    //Set to true if the authenticator has actually been applied to the account.
    @JsonProperty("fully_enrolled")
    public boolean fullyEnrolled;
    @JsonProperty("shared_secret")
    private String sharedSecret;
    @JsonProperty("serial_number")
    private String serialNumber;
    @JsonProperty("revocation_code")
    private String revocationCode;
    @JsonProperty("uri")
    private String URI;
    @JsonProperty("server_time")
    private long serverTime;
    @JsonProperty("account_name")
    private String accountName;
    @JsonProperty("token_gid")
    private String tokenGID;
    @JsonProperty("identity_secret")
    private String identitySecret;
    @JsonProperty("secret_1")
    private String secret1;
    @JsonProperty("status")
    private int status;
    @JsonProperty("device_id")
    private String deviceID;
    private SessionData session;
    private final Pattern confRegex = Pattern.compile("<div class=\"mobileconf_list_entry\" id=\"conf[0-9]+\" data-confid=\"(\\d+)\" data-key=\"(\\d+)\" data-type=\"(\\d+)\" data-creator=\"(\\d+)\"");

    public boolean acceptConfirmation(Confirmation conf) {
        return sendConfirmationAjax(conf, "allow");
    }

    public boolean denyConfirmation(Confirmation conf) {
        return sendConfirmationAjax(conf, "cancel");
    }

    public boolean deactivateAuthenticator() {
        return this.deactivateAuthenticator(2);
    }

    public boolean deactivateAuthenticator(int scheme) {
        final Map<String, String> postData = new HashMap<>();
        postData.put("steamid", String.valueOf(session.getSteamID()));
        postData.put("steamguard_scheme", String.valueOf(scheme));
        postData.put("revocation_code", revocationCode);
        postData.put("access_token", session.getOAuthToken());

        try {
            String response = SteamWeb.mobileLoginRequest(APIEndpoints.STEAMAPI_BASE +
                    "/ITwoFactorService/RemoveAuthenticator/v0001", new HttpParameters(postData, HttpMethod.POST));

            SteamResponse steamResponse = Json.getInstance().mapper().readValue(response, new TypeReference<SteamResponse<RemoveAuthenticatorResponse>>() {
            });
            RemoveAuthenticatorResponse removeResponse = (RemoveAuthenticatorResponse) steamResponse.getResponse();

            return !(removeResponse == null || !removeResponse.isSuccess());
        } catch (Exception e) {
            LOG.error("Deactivate authenticator error", e);
            return false;
        }
    }

    public Confirmation[] fetchConfirmations() throws WGTokenInvalidException {
        final String url = generateConfirmationURL();

        SteamWeb.addCookies(session);

        final String response = SteamWeb.fetch(url, new HttpParameters(HttpMethod.GET));

        if (response == null || !confRegex.matcher(response).find()) {
            if (response == null || !response.contains("<div>Nothing to confirm</div>")) {
                throw new WGTokenInvalidException();
            }
            return new Confirmation[0];
        }

        final Matcher confirmation = confRegex.matcher(response);

        final List<Confirmation> ret = new ArrayList<>();

        while (confirmation.find()) {

            final long confId = new BigInteger(confirmation.group(1)).longValue();

            final long confKey = new BigInteger(confirmation.group(2)).longValue();

            final int confType = Integer.parseInt(confirmation.group(3));

            final long confCreator = new BigInteger(confirmation.group(4)).longValue();

            ret.add(new Confirmation(confId, confKey, confType, confCreator));
        }

        return ret.toArray(new Confirmation[ret.size()]);
    }

    public String generateSteamGuardCode() {
        return generateSteamGuardCodeForTime(TimeAligner.getSteamTime());
    }

    public String generateSteamGuardCodeForTime(long time) {
        if (sharedSecret == null || sharedSecret.length() == 0) return "";

        // Shared secret is our key
        byte[] sharedSecretBytes = Base64.getDecoder().decode(sharedSecret);
        byte[] timeArray = new byte[8];

        // Time for code
        time /= 30L;
        for (int i = 8; i > 0; i--) {
            timeArray[i - 1] = (byte) time;
            time >>= 8;
        }

        // Generate hmac
        byte[] codeArray = new byte[5];
        try {
            byte[] hashedData = HMACSHA1.calculate(timeArray, sharedSecretBytes);

            // the last 4 bits of the hashedData say where the code starts
            // (e.g. if last 4 bit are 1100, we start at byte 12)
            byte b = (byte) (hashedData[19] & 0xF);

            int codePoint = (hashedData[b] & 0x7F) << 24 | (hashedData[b + 1] & 0xFF) << 16 | (hashedData[b + 2] & 0xFF) << 8 | (hashedData[b + 3] & 0xFF);

            for (int i = 0; i < 5; ++i) {
                codeArray[i] = steamGuardCodeTranslations[codePoint % steamGuardCodeTranslations.length];
                codePoint /= steamGuardCodeTranslations.length;
            }
        } catch (InvalidKeyException e) {
            LOG.error("Failed to generate hmac", e);
            return null;
        }
        return IOHelper.decode(codeArray);
    }

    public long getConfirmationTradeOfferID(Confirmation conf) {
        if (conf.getConfType() != Confirmation.ConfirmationType.TRADE) {
            throw new IllegalArgumentException("conf must be a trade confirmation.");
        }

        return conf.getCreator();
    }

    private String generateConfirmationURL() {
        return generateConfirmationURL("conf");
    }

    private String generateConfirmationURL(String tag) {
        String endpoint = APIEndpoints.COMMUNITY_BASE + "/mobileconf/conf?";
        String queryString = generateConfirmationQueryParams(tag);

        return endpoint + queryString;
    }

    private String generateConfirmationQueryParams(String tag) {
        if (deviceID == null || deviceID.isEmpty())
            throw new IllegalArgumentException("Device ID is not present");

        Map<String, String> queryParams = generateConfirmationQueryParamsAsNVC(tag);

        return "p=" + queryParams.get("p") + "&a=" + queryParams.get("a") + "&k=" + queryParams.get("k") + "&t="
                + queryParams.get("t") + "&m=android&tag=" + queryParams.get("tag");
    }

    private Map<String, String> generateConfirmationQueryParamsAsNVC(String tag) {
        if (deviceID == null || deviceID.isEmpty())
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

        try {
            RefreshSessionDataResponse refreshResponse = Json.getInstance().mapper().readValue(response,
                    new TypeReference<SteamResponse<RefreshSessionDataResponse>>() {
                    });
            if (refreshResponse.token == null) return false;

            String token = session.getSteamID() + "%7C%7C" + refreshResponse.token;
            String tokenSecure = session.getSteamID() + "%7C%7C" + refreshResponse.tokenSecure;

            session.setSteamLogin(token);
            session.setSteamLoginSecure(tokenSecure);
        } catch (IOException e) {
            LOG.error("Couldn't refresh a session", e);
        }

        return true;
    }

    private ConfirmationDetailsResponse getConfirmationDetails(Confirmation conf) {
        String url = APIEndpoints.COMMUNITY_BASE + "/mobileconf/details/" + conf.getId() + "?";
        String queryString = generateConfirmationQueryParams("details");
        url += queryString;

        SteamWeb.addCookies(session);

        String response = SteamWeb.fetch(url, new HttpParameters(HttpMethod.GET));
        if (response.isEmpty()) return null;

        ConfirmationDetailsResponse confResponse = null;
        try {
            confResponse = Json.getInstance().mapper().readValue(response, ConfirmationDetailsResponse.class);
        } catch (IOException e) {
            e.printStackTrace();
        }
        if (confResponse == null) return null;

        return confResponse;
    }

    private boolean sendConfirmationAjax(Confirmation conf, String op) {
        String url = APIEndpoints.COMMUNITY_BASE + "/mobileconf/ajaxop";
        String queryString = "?op=" + op + "&";
        queryString += generateConfirmationQueryParams(op);
        queryString += "&cid=" + conf.getId() + "&ck=" + conf.getKey();
        url += queryString;

        SteamWeb.addCookies(session);

        String response = SteamWeb.fetch(url, new HttpParameters(HttpMethod.GET));

        if (response == null) return false;

        SendConfirmationResponse confResponse = null;
        try {
            confResponse = Json.getInstance().mapper().readValue(response, SendConfirmationResponse.class);
        } catch (IOException e) {
            LOG.error("Could't read confirmation response", e);
            return false;
        }

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
            array[n4] = (byte) time;
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

    public String getAccountName() {
        return accountName;
    }
}
