package com.vitaxa.steamauth.model;

public enum LinkResult {
    MUST_PROVIDE_PHONE_NUMBER, //No phone number on the account
    MUST_REMOVE_PHONE_NUMBER, //A phone number is already on the account
    AWAITING_FINALIZATION, //Must provide an SMS code
    GENERAL_FAILURE, //General failure (really now!)
    AUTHENTICATOR_PRESENT
}
