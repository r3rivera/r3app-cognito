package com.r2playground.service.auth.cognito;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;

import java.util.HashMap;
import java.util.Map;

public abstract class AwsCognitoBaseProvider {

    protected static final String USER_NOT_FOUND = "User Not Found";
    protected static final String INVALID_USER_PASSWORD = "Invalid Credentials";
    protected static final String PASSWORD_RESET_REQUIRED = "Password Expired";
    protected static final String INVALID_PASSWORD_VALUE = "Invalid Password";
    protected static final String CONFIRMATION_CODE_EXPIRED = "Expired Confirmation Code";
    protected static final String CONFIRMATION_CODE_USER_MISMATCHED = "Invalid User for Code";

    protected static Map<String, Integer> errorCodes;

    static{
        errorCodes = new HashMap<>();
        errorCodes.put(USER_NOT_FOUND, 2000);
        errorCodes.put(INVALID_USER_PASSWORD, 2001);
        errorCodes.put(PASSWORD_RESET_REQUIRED, 2002);
        errorCodes.put(INVALID_PASSWORD_VALUE, 2003);
        errorCodes.put(CONFIRMATION_CODE_EXPIRED, 2004);
        errorCodes.put(CONFIRMATION_CODE_USER_MISMATCHED, 2005);
    }

    private AwsCognitoCredentials credentials;
    private AWSCognitoIdentityProvider identityProvider;

    public AwsCognitoBaseProvider(AwsCognitoCredentials credentials){

        this.credentials = credentials;

        final AWSStaticCredentialsProvider provider = new AWSStaticCredentialsProvider(credentials);
        this.identityProvider = AWSCognitoIdentityProviderClientBuilder.standard().withCredentials(provider)
                .withRegion(credentials.getRegion()).build();
    }

    protected AwsCognitoConfig getAwsCognitoConfig(){
        return credentials;
    }

    protected AWSCognitoIdentityProvider getIdentityProvider(){
        return identityProvider;
    }
}
