package com.vitaxa.steamauth.model;

public class Confirmation {
    public String id;
    public String key;
    public String description;

    public ConfirmationType confType;

    public Confirmation(String id, String key, String description) {
        this.id = id;
        this.key = key;
        this.description = description;

        if (description == null || description.isEmpty()) {
            confType = ConfirmationType.UNKNOWN;
        } else if (description.startsWith("Confirm")) {
            confType = ConfirmationType.GENERIC_CONFIRMATION;
        } else if (description.startsWith("Trade with")) {
            confType = ConfirmationType.TRADE;
        } else if (description.startsWith("Sell -")) {
            confType = ConfirmationType.MARKET_SELL_TRANSACTION;
        }
    }

    public String getId() {
        return id;
    }

    public String getKey() {
        return key;
    }

    public String getDescription() {
        return description;
    }

    public ConfirmationType getConfType() {
        return confType;
    }

    public enum ConfirmationType {
        GENERIC_CONFIRMATION,
        TRADE,
        MARKET_SELL_TRANSACTION,
        UNKNOWN;
    }
}
