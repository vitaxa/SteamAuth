package com.vitaxa.steamauth;

import java.io.Serializable;

public class WGTokenExpiredException extends Throwable implements Serializable {
    private static final long serialVersionUID = -1118831568726071256L;

    public WGTokenExpiredException(String message) {
        super(message);
    }

    public WGTokenExpiredException(Throwable exc) {
        super(exc);
    }

    public WGTokenExpiredException(String message, Throwable exc) {
        super(message, exc);
    }

    @Override
    public String toString() {
        return getMessage();
    }
}
