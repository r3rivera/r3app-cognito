package com.r2playground.service.auth.domain;

public class AwsUserAttributes {
    private String name;
    private String values;

    public AwsUserAttributes(String name, String values) {
        this.name = name;
        this.values = values;
    }

    public String getName() {
        return name;
    }

    public String getValues() {
        return values;
    }
}
