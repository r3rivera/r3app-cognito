package com.r2playground.service.auth.cognito;

import com.r2playground.service.auth.domain.AwsCognitoResponse;
import com.r2playground.service.auth.domain.AwsUser;
import com.r2playground.service.auth.domain.AwsUserAttributes;
import com.r2playground.service.auth.domain.UserDetail;

import java.util.List;

public interface AwsCognitoProvider {

    boolean createUser(AwsUser user);
    AwsCognitoResponse loginUser(String username, String password);
    AwsCognitoResponse respondToAuthChallenge(String username, String newPassword, String challengeSessionId);
    boolean deleteUserDetailByAdmin(String username);
    UserDetail getUserDetailsByAdmin(String username, List<AwsUserAttributes> userAttributes);
    AwsUser getUserDetails(String accessToken,  List<AwsUserAttributes> userAttributes);
    AwsCognitoResponse changePassword(String accessToken, String oldPassword, String newPassword);
    AwsCognitoResponse forgotPassword(String username);
    AwsCognitoResponse confirmForgotPassword(String username, String newPassword, String confirmationCode);
    AwsCognitoResponse resendTempPassword(String username);
    boolean generateCodeForEmailVerification(String accessToken);
    boolean verifyEmailByCode(String accessToken, String code);

}
