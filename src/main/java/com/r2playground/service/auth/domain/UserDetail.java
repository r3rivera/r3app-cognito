package com.r2playground.service.auth.domain;

import java.util.List;

public class UserDetail implements AwsUser {

    private String userName;
    private String firstName;
    private String lastName;
    private String email;
    private String phoneNumber;
    private List<AwsUserAttributes> attributes;

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    @Override
    public List<AwsUserAttributes> getAttributes() {
        return attributes;
    }

    public void setAttributes(List<AwsUserAttributes> attributes) {
        this.attributes = attributes;
    }
}
