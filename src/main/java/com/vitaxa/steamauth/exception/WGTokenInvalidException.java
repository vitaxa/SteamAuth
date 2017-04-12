package com.vitaxa.steamauth.exception;

import java.io.Serializable;

public class WGTokenInvalidException extends Throwable implements Serializable {

    private static final long serialVersionUID = 2947323190503240341L;

    public WGTokenInvalidException(String message) {
        super(message);
    }

    public WGTokenInvalidException(Throwable exc) {
        super(exc);
    }

    public WGTokenInvalidException(String message, Throwable exc) {
        super(message, exc);
    }

    @Override
    public String toString() {
        return getMessage();
    }
}
