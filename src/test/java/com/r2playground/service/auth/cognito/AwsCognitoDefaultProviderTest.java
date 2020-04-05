package com.r2playground.service.auth.cognito;

import com.r2playground.service.auth.domain.AwsCognitoResponse;
import com.r2playground.service.auth.domain.UserDetail;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class AwsCognitoDefaultProviderTest {

    private static String TEST_EMAIL = "";
    private static AwsCognitoDefaultProvider provider;

    @BeforeAll
    public static void init(){
        final String accessKey = System.getenv("AccessKey");
        final String secretKey = System.getenv("SecretKey");
        final String cognitoClientId = System.getenv("AwsClientId");
        final String userPoolId = System.getenv("AwsUserPool");
        final String region = System.getenv("AwsRegion");
        TEST_EMAIL = System.getenv("TestEmail");

        final AwsCognitoCredentials credentials = new AwsCognitoCredentials();
        credentials.setAwsAccessKey(accessKey);
        credentials.setAwsSecretKey(secretKey);
        credentials.setClientId(cognitoClientId);
        credentials.setPoolId(userPoolId);
        credentials.setRegion(region);

        System.out.println(credentials);
        provider = new AwsCognitoDefaultProvider(credentials);
    }

    @Test
    @DisplayName("Create a New User")
    public void createUser(){
        assertNotNull(provider);
        assertNotNull(TEST_EMAIL);
        final UserDetail userDetail = new UserDetail();
        userDetail.setEmail(TEST_EMAIL);
        userDetail.setFirstName("SomeUSer");
        userDetail.setLastName("SomeLast");
        userDetail.setUserName(TEST_EMAIL);
        userDetail.setPhoneNumber("+18005559999");
        assertTrue(provider.createUser(userDetail));
    }

    @Test
    public void loginWithTempPassword(){
        assertNotNull(TEST_EMAIL);

        final AwsCognitoResponse tempResp = provider.loginUser(TEST_EMAIL, "P4H.1IWb");
        assertNotNull(tempResp);
        assertTrue(tempResp.isSuccess());
        assertNotNull(tempResp.getResult());

        System.out.println(tempResp.getResult().getChallengeSessionId());
        System.out.println(tempResp.getResult().getAccessToken());
        System.out.println(tempResp.getResult().getRefreshToken());

        final AwsCognitoResponse changePasswd = provider.respondToAuthChallenge(TEST_EMAIL, "T3stPsswd!",
                tempResp.getResult().getChallengeSessionId());
        assertTrue(changePasswd.isSuccess());
        assertNotNull(changePasswd.getResult());

        System.out.println(changePasswd.getResult().getChallengeSessionId());
        System.out.println(changePasswd.getResult().getAccessToken());
        System.out.println(changePasswd.getResult().getRefreshToken());

    }

}
