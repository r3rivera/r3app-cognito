package com.r2playground.service.auth.domain;

public class AwsCognitoResponse {

    private boolean success;
    private AwsCognitoResult result;
    private AwsCognitoError error;


    public AwsCognitoResponse(AwsCognitoError error) {
        this.success = false;
        this.error = error;
    }
    public AwsCognitoResponse(AwsCognitoResult result, boolean success) {
        this.success = success;
        this.result = result;
    }

    public AwsCognitoResult getResult() {
        return result;
    }

    public boolean isSuccess() {
        return success;
    }

    public AwsCognitoError getError() {
        return error;
    }
}
