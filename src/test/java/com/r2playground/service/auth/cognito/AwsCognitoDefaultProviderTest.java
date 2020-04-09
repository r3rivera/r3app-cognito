package com.r2playground.service.auth.cognito;

import com.r2playground.service.auth.domain.AwsCognitoResponse;
import com.r2playground.service.auth.domain.UserDetail;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class AwsCognitoDefaultProviderTest {

    private static String TEST_EMAIL = null;
    private static AwsCognitoProvider provider;

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
        provider = new AwsCognitoUserPasswordProvider(credentials);
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
        userDetail.setPassword("S0meDumbPasswd!");
        userDetail.setUserName(TEST_EMAIL);
        userDetail.setPhoneNumber("+18005559999");
        assertTrue(provider.createUser(userDetail));
    }


    @Test
    @DisplayName("Login with user provided password")
    public void loginWithUserProvidedPassword(){
        assertNotNull(TEST_EMAIL);
        final AwsCognitoResponse tempResp = provider.loginUser(TEST_EMAIL, "S0meDumbPasswd!");
        assertNotNull(tempResp);
        assertTrue(tempResp.isSuccess());
        assertNotNull(tempResp.getResult());

        System.out.println("Challenge Session ID :: " + tempResp.getResult().getChallengeSessionId());
        System.out.println("Access Token :: " + tempResp.getResult().getAccessToken());
        System.out.println("Refresh Token :: " + tempResp.getResult().getRefreshToken());

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
