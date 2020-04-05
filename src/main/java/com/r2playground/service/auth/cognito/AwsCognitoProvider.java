package com.r2playground.service.auth.cognito;

import com.r2playground.service.auth.domain.AwsUser;

public interface AwsCognitoProvider {

    boolean createUser(AwsUser user);

}
