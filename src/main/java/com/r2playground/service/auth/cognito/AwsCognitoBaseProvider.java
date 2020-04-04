package com.r2playground.service.auth.cognito;

import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;

public abstract class AwsCognitoBaseProvider {

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
