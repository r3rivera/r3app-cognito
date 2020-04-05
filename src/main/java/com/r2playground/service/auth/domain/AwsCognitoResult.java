package com.r2playground.service.auth.domain;

public class AwsCognitoResult {

    private String challengeSessionId;
    private String accessToken;
    private String refreshToken;
    private AwsResponseType responseType;

    public AwsCognitoResult(String challengeSessionId, String accessToken, String refreshToken, AwsResponseType responseType) {
        this.challengeSessionId = challengeSessionId;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.responseType = responseType;
    }

    public String getChallengeSessionId() {
        return challengeSessionId;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }
}
