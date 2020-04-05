package com.r2playground.service.auth.cognito;

import com.amazonaws.auth.AWSCredentials;

public class AwsCognitoCredentials implements AWSCredentials, AwsCognitoConfig {

    private String region;
    private String awsAccessKey;
    private String awsSecretKey;
    private String clientId;
    private String poolId;

    @Override
    public String getAWSAccessKeyId() {
        return awsAccessKey;
    }

    public void setAwsAccessKey(String awsAccessKey) {
        this.awsAccessKey = awsAccessKey;
    }

    public void setAwsSecretKey(String awsSecretKey) {
        this.awsSecretKey = awsSecretKey;
    }

    @Override
    public String getAWSSecretKey() {
        return awsSecretKey;
    }

    public String getRegion() {
        return region;
    }

    public void setRegion(String region) {
        this.region = region;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getPoolId() {
        return poolId;
    }

    public void setPoolId(String poolId) {
        this.poolId = poolId;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("AwsCognitoCredentials{");
        sb.append("region='").append(region).append('\'');
        sb.append(", awsAccessKey='").append(awsAccessKey).append('\'');
        sb.append(", awsSecretKey='").append(awsSecretKey).append('\'');
        sb.append(", clientId='").append(clientId).append('\'');
        sb.append(", poolId='").append(poolId).append('\'');
        sb.append('}');
        return sb.toString();
    }
}
