package com.r2playground.service.auth.domain;

public enum AwsResponseType {

    //Value when after a successful login
    DEFAULT("DEFAULT"),
    FORCE_CHANGE_PASSWORD("FORCE_CHANGE_PASSWORD"),
    //Value when temporary password is needed
    NEW_PASSWORD_REQUIRED("NEW_PASSWORD_REQUIRED");

    private String type;

    AwsResponseType(String type) {
        this.type = type;
    }


    public static AwsResponseType getType(String type) {

        if (type == null) {
            return DEFAULT;
        }
        switch (type) {
            case "NEW_PASSWORD_REQUIRED":
                return NEW_PASSWORD_REQUIRED;
            case "FORCE_CHANGE_PASSWORD":
                return FORCE_CHANGE_PASSWORD;
        }
        return DEFAULT;
    }

    public String getValue() {
        return this.type;
    }


}
