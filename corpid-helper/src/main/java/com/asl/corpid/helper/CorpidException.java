package com.asl.corpid.helper;

public class CorpidException extends RuntimeException {
    public CorpidException(String message) {
        super(message);
    }

    public CorpidException(String message, Throwable cause) {
        super(message, cause);
    }
}
