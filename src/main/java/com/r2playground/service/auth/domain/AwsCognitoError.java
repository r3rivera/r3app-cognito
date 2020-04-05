package com.r2playground.service.auth.domain;

public class AwsCognitoError {
    private int code;
    private String message;

    public AwsCognitoError(int code, String message) {
        this.code = code;
        this.message = message;
    }

    public int getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }
}
