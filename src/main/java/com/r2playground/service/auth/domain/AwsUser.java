package com.r2playground.service.auth.domain;

import java.util.List;

public interface AwsUser {

    String getUserName();
    String getFirstName();
    String getLastName();
    String getPassword();
    String getEmail();
    String getPhoneNumber();
    List<AwsUserAttributes> getAttributes();


}
