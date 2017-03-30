package com.vitaxa.steamauth;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.HashMap;
import java.util.Map;

import com.vitaxa.steamauth.APIEndpoints;

public class AuthenticatorLinker {
    /// <summary>
    /// Set to register a new phone number when linking. If a phone number is not set on the account, this must be set. If a phone number is set on the account, this must be null.
    /// </summary>
    public String phoneNumber = null;

    /// <summary>
    /// Randomly-generated device ID. Should only be generated once per linker.
    /// </summary>
    public String deviceID;// { get; private set; }

    /// <summary>
    /// After the initial link step, if successful, this will be the SteamGuard data for the account. PLEASE save this somewhere after generating it; it's vital data.
    /// </summary>
    public SteamGuardAccount LinkedAccount;// { get; private set; }

    /// <summary>
    /// True if the authenticator has been fully finalized.
    /// </summary>
    public boolean Finalized = false;

    private SessionData session;
    private CookieContainer cookies;

    public AuthenticatorLinker(SessionData session) {
        this.session = session;
        this.deviceID = GenerateDeviceID();

        this.cookies = new CookieContainer();
        session.addCookies(cookies);
    }

    public LinkResult AddAuthenticator() {
        boolean hasPhone = hasPhoneAttached();
        if (hasPhone && PhoneNumber != null)
            return LinkResult.MUST_REMOVE_PHONE_NUMBER;
        if (!hasPhone && PhoneNumber == null)
            return LinkResult.MUST_PROVIDE_PHONE_NUMBER;

        if (!hasPhone) {
            if (!addPhoneNumber()) {
                return LinkResult.GENERAL_FAILURE;
            }
        }
        Map<String, Object> postData = new HashMap<>();
        postData.put("access_token", session.OAuthToken);
        postData.put("steamid", session.SteamID);
        postData.put("authenticator_type", "1");
        postData.put("device_identifier", this.deviceID);
        postData.put("sms_phone_id", "1");

        String response = SteamWeb.MobileLoginRequest(APIEndpoints.STEAMAPI_BASE + "/ITwoFactorService/AddAuthenticator/v0001", "POST", postData);
        if (response == null) return LinkResult.GENERAL_FAILURE;

        String addAuthenticatorResponse = new Gson().fromJson(response, AddAuthenticatorResponse.class);
        if (addAuthenticatorResponse == null || addAuthenticatorResponse.response == null) {
            return LinkResult.GENERAL_FAILURE;
        }
        if (addAuthenticatorResponse.response.Status == 29) {
            return LinkResult.AUTHENTICATOR_PRESENT;
        }

        if (addAuthenticatorResponse.response.Status != 1) {
            return LinkResult.GENERAL_FAILURE;
        }

        this.LinkedAccount = addAuthenticatorResponse.Response;
        LinkedAccount.session = this.session;
        LinkedAccount.deviceID = this.deviceID;

        return LinkResult.AWAITING_FINALIZATION;
    }

    public FinalizeResult finalizeAddAuthenticator(String smsCode) {
        if (phoneNumber != null && !phoneNumber.isEmpty() && !this.checkSMSCode) {
            return FinalizeResult.BAD_SMS_CODE;
        }

        Map<String, Object> postData = new HashMap<>();
        postData.put("steamid", session.SteamID);
        postData.put("access_token", session.OAuthToken);
        postData.put("activation_code", smsCode);
        int tries = 0;
        while (tries <= 30) {
            postData.put("authenticator_code", LinkedAccount.GenerateSteamGuardCode());
            postData.put("authenticator_time", TimeAligner.GetSteamTime().ToString());

            String response = SteamWeb.MobileLoginRequest(APIEndpoints.STEAMAPI_BASE + "/ITwoFactorService/FinalizeAddAuthenticator/v0001", "POST", postData);
            if (response == null) return FinilizeResult.GENERAL_FAILURE;

            String finalizeResponse = new Gson().fromJson(response, FinalizeAuthenticatorResponse.class);
            JsonObject responseObject = new JsonParser().parse(response).getAsJsonObject();
            JsonObject resultResponse = responseObject.get("response").getAsJsonObject();

            if (finalizeResponse == null || resultResponse == null) {
                return FinalizeResult.GENERAL_FAILURE;
            }


        }
    }
    private boolean checkSMSCode(String smsCode)
        {
        Map<String, Object> postData = new HashMap<>();
        postData.put("op", "check_sms_code");
        postData.put("arg", smsCode);
        postData.put("sessionid", session.SessionID);

        String response = SteamWeb.Request(APIEndpoints.COMMUNITY_BASE + "/steamguard/phoneajax", "POST", postData, _cookies);
        if (response == null) return false;
        String addPhoneNumberResponse = new Gson().fromJson(response, AddPhoneResponse.class);

        JsonObject responseObject = new JsonParser().parse(response).getAsJsonObject();
        return addPhoneNumberResponse.Success;
    }

    public enum LinkResult {
        MUST_PROVIDE_PHONE_NUMBER, //No phone number on the account
        MUST_REMOVE_PHONE_NUMBER, //A phone number is already on the account
        AWAITING_FINALIZATION, //Must provide an SMS code
        GENERAL_FAILURE, //General failure (really now!)
        AUTHENTICATOR_PRESENT
    }

    public enum FinalizeResult {
        BAD_SMS_CODE,
        UNABLE_TO_GENERATE_CORRECT_CODES,
        SUCCESS,
        GENERAL_FAILURE
    }
}
