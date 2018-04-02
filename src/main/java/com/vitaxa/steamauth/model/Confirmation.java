package com.vitaxa.steamauth.model;

public class Confirmation {

    // The ID of this confirmation
    private final Long id;

    // The unique key used to act upon this confirmation.
    private final Long key;

    // The value of the data-type HTML attribute returned for this contribution.
    private final Integer type;

    // Represents either the Trade Offer ID or market transaction ID that caused this confirmation to be created.
    private final Long creator;

    private ConfirmationType confType;

    public Confirmation(Long id, Long key, Integer type, Long creator) {
        this.id = id;
        this.key = key;
        this.type = type;
        this.creator = creator;

        // Do a switch simply because we're not 100% certain of all the possible types.
        switch (type) {
            case 1:
                confType = ConfirmationType.GENERIC_CONFIRMATION;
                break;
            case 2:
                confType = ConfirmationType.TRADE;
                break;
            case 3:
                confType = ConfirmationType.MARKET_SELL_TRANSACTION;
                break;
            default:
                confType = ConfirmationType.UNKNOWN;

        }
    }

    public Long getId() {
        return id;
    }

    public Long getKey() {
        return key;
    }

    public Integer getType() {
        return type;
    }

    public Long getCreator() {
        return creator;
    }

    public ConfirmationType getConfType() {
        return confType;
    }

    @Override
    public String toString() {
        return "Confirmation{" +
                "id='" + id + '\'' +
                ", key='" + key + '\'' +
                ", type=" + type +
                ", creator=" + creator +
                ", confType=" + confType +
                '}';
    }

    public enum ConfirmationType {
        GENERIC_CONFIRMATION,
        TRADE,
        MARKET_SELL_TRANSACTION,
        UNKNOWN;
    }
}
