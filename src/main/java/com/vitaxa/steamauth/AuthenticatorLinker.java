package com.vitaxa.steamauth;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.type.TypeReference;
import com.vitaxa.steamauth.helper.Json;
import com.vitaxa.steamauth.http.HttpMethod;
import com.vitaxa.steamauth.http.HttpParameters;
import com.vitaxa.steamauth.model.FinalizeResult;
import com.vitaxa.steamauth.model.LinkResult;
import com.vitaxa.steamauth.model.SessionData;
import com.vitaxa.steamauth.model.SteamResponse;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.http.client.CookieStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

public class AuthenticatorLinker {

    private static final Logger LOG = LoggerFactory.getLogger(AuthenticatorLinker.class);

    /**
     * Set to register a new phone number when linking.
     * If a phone number is not set on the account, this must be set.
     * If a phone number is set on the account, this must be null.
     */
    private String phoneNumber = null;

    /**
     * Randomly-generated device ID. Should only be generated once per linker.
     */
    private String deviceID;

    /**
     * After the initial link step, if successful, this will be the SteamGuard data for the account.
     * PLEASE save this somewhere after generating it; it's vital data.
     */
    private SteamGuardAccount linkedAccount;

    /**
     * True if the authenticator has been fully finalized.
     */
    private boolean finalized = false;

    private SessionData session;
    private CookieStore cookieStore;

    public AuthenticatorLinker(SessionData session) {
        this.session = session;
        this.deviceID = generateDeviceID();

        SteamWeb.addCookies(session);
    }

    public static String generateDeviceID() {
        // Generate 8 random bytes
        final byte[] randomBytes = new byte[8];
        final SecureRandom random = new SecureRandom();
        random.nextBytes(randomBytes);

        // Generate sha1 hash
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] hashedBytes = md.digest(randomBytes);

            String random32 = DigestUtils.sha1Hex(hashedBytes).substring(0, 32);

            return "android:" + splitOnRatios(random32, new int[]{8, 4, 4, 4, 12}, "-");
        } catch (NoSuchAlgorithmException e) {
            LOG.error("Failed to generate sha1 hash", e);
            return "";
        }
    }

    private static String splitOnRatios(String str, int[] ratios, String intermediate) {
        StringBuilder result = new StringBuilder();

        int pos = 0;
        for (int index = 0; index < ratios.length; index++) {
            result.append(str.substring(pos, Math.min(pos + ratios[index], str.length())));
            pos = ratios[index];

            if (index < ratios.length - 1)
                result.append(intermediate);
        }

        return result.toString();
    }

    public LinkResult addAuthenticator() {
        boolean hasPhone = hasPhoneAttached();
        if (hasPhone && phoneNumber != null)
            return LinkResult.MUST_REMOVE_PHONE_NUMBER;
        if (!hasPhone && phoneNumber == null)
            return LinkResult.MUST_PROVIDE_PHONE_NUMBER;

        if (!hasPhone) {
            if (!addPhoneNumber()) {
                return LinkResult.GENERAL_FAILURE;
            }
        }
        Map<String, String> postData = new HashMap<>();
        postData.put("access_token", session.getOAuthToken());
        postData.put("steamid", String.valueOf(session.getSteamID()));
        postData.put("authenticator_type", "1");
        postData.put("device_identifier", deviceID);
        postData.put("sms_phone_id", "1");

        String response = SteamWeb.mobileLoginRequest(APIEndpoints.STEAMAPI_BASE + "/ITwoFactorService/AddAuthenticator/v0001",
                new HttpParameters(postData, HttpMethod.POST));
        if (response == null) return LinkResult.GENERAL_FAILURE;

        AddAuthenticatorResponse addAuthenticatorResponse = null;
        try {
            addAuthenticatorResponse = Json.getInstance().mapper().readValue(response, AddAuthenticatorResponse.class);
        } catch (IOException e) {
            LOG.error("Couldn't read authenticator response", e);
        }

        if (addAuthenticatorResponse == null || addAuthenticatorResponse.response == null) {
            return LinkResult.GENERAL_FAILURE;
        }

        if (addAuthenticatorResponse.response.getStatus() == 29) {
            return LinkResult.AUTHENTICATOR_PRESENT;
        }

        if (addAuthenticatorResponse.response.getStatus() != 1) {
            return LinkResult.GENERAL_FAILURE;
        }

        linkedAccount = addAuthenticatorResponse.response;
        linkedAccount.setSession(this.session);
        linkedAccount.setDeviceID(this.deviceID);

        return LinkResult.AWAITING_FINALIZATION;
    }

    public FinalizeResult finalizeAddAuthenticator(String smsCode) {
        if (phoneNumber != null && !phoneNumber.isEmpty() && !checkSMSCode(smsCode)) {
            return FinalizeResult.BAD_SMS_CODE;
        }

        Map<String, String> postData = new HashMap<>();
        postData.put("steamid", String.valueOf(session.getSteamID()));
        postData.put("access_token", session.getOAuthToken());
        postData.put("activation_code", smsCode);
        int tries = 0;
        while (tries <= 30) {
            postData.put("authenticator_code", linkedAccount.generateSteamGuardCode());
            postData.put("authenticator_time", String.valueOf(TimeAligner.getSteamTime()));

            String response = SteamWeb.mobileLoginRequest(APIEndpoints.STEAMAPI_BASE + "/ITwoFactorService/FinalizeAddAuthenticator/v0001",
                    new HttpParameters(postData, HttpMethod.POST));

            if (response == null) return FinalizeResult.GENERAL_FAILURE;

            final SteamResponse<FinalizeAuthenticatorResponse> steamResponse = Json.getInstance().fromJson(response,
                    new TypeReference<SteamResponse<FinalizeAuthenticatorResponse>>() {
                    });

            FinalizeAuthenticatorResponse finalizeResponse = (FinalizeAuthenticatorResponse) steamResponse.getResponse();

            if (finalizeResponse == null) return FinalizeResult.GENERAL_FAILURE;

            if (finalizeResponse.status == 89) {
                return FinalizeResult.BAD_SMS_CODE;
            }

            if (finalizeResponse.status == 88) {
                if (tries >= 30)
                    return FinalizeResult.UNABLE_TO_GENERATE_CORRECT_CODES;
            }

            if (!finalizeResponse.success) return FinalizeResult.GENERAL_FAILURE;

            if (finalizeResponse.wantMore) {
                tries++;
                continue;
            }

            this.linkedAccount.fullyEnrolled = true;

            return FinalizeResult.SUCCESS;
        }

        return FinalizeResult.GENERAL_FAILURE;
    }

    private boolean checkSMSCode(String smsCode) {
        Map<String, String> postData = new HashMap<>();
        postData.put("op", "check_sms_code");
        postData.put("arg", smsCode);
        postData.put("sessionid", session.getSessionID());

        String response = SteamWeb.fetch(APIEndpoints.COMMUNITY_BASE + "/steamguard/phoneajax",
                new HttpParameters(postData, HttpMethod.POST));

        if (response == null) return false;

        final AddPhoneResponse addPhoneNumberResponse = Json.getInstance().fromJson(response, AddPhoneResponse.class);

        return addPhoneNumberResponse.success;
    }

    private boolean addPhoneNumber() {
        Map<String, String> postData = new HashMap<>();
        postData.put("op", "add_phone_number");
        postData.put("arg", phoneNumber);
        postData.put("sessionid", session.getSessionID());

        String response = SteamWeb.fetch(APIEndpoints.COMMUNITY_BASE + "/steamguard/phoneajax",
                new HttpParameters(postData, HttpMethod.POST));

        if (response == null) return false;

        final AddPhoneResponse addPhoneNumberResponse = Json.getInstance().fromJson(response, AddPhoneResponse.class);

        return addPhoneNumberResponse.success;
    }

    private boolean hasPhoneAttached() {
        Map<String, String> postData = new HashMap<>();
        postData.put("op", "has_phone");
        postData.put("arg", "null");
        postData.put("sessionid", session.getSessionID());

        String response = SteamWeb.fetch(APIEndpoints.COMMUNITY_BASE + "/steamguard/phoneajax",
                new HttpParameters(postData, HttpMethod.POST));

        if (response == null) return false;

        HasPhoneResponse hasPhoneResponse = Json.getInstance().fromJson(response, HasPhoneResponse.class);

        return hasPhoneResponse.hasPhone;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    public String getDeviceID() {
        return deviceID;
    }

    public SteamGuardAccount getLinkedAccount() {
        return linkedAccount;
    }

    public boolean isFinalized() {
        return finalized;
    }

    public SessionData getSession() {
        return session;
    }

    private final class AddAuthenticatorResponse {
        @JsonProperty("response")
        public SteamGuardAccount response;
    }

    private final class AddPhoneResponse {
        @JsonProperty("success")
        public boolean success;
    }

    private final class FinalizeAuthenticatorResponse {
        @JsonProperty("status")
        public int status;

        @JsonProperty("server_time")
        public long serverTime;

        @JsonProperty("want_more")
        public boolean wantMore;

        @JsonProperty("success")
        public boolean success;
    }

    private final class HasPhoneResponse {
        @JsonProperty("has_phone")
        public boolean hasPhone;
    }
}
