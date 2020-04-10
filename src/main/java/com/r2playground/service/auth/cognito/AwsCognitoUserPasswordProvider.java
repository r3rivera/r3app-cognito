package com.r2playground.service.auth.cognito;

import com.amazonaws.services.cognitoidp.model.*;
import com.r2playground.service.auth.domain.AwsCognitoResponse;
import com.r2playground.service.auth.domain.AwsUser;
import com.r2playground.service.auth.exception.AuthException;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class AwsCognitoUserPasswordProvider extends AwsCognitoDefaultProvider {

    public AwsCognitoUserPasswordProvider(AwsCognitoCredentials credentials){
        super(credentials);
    }

    /**
     * Creates a new user within Cognito
     * @param user
     * @return
     */
    public boolean createUser(AwsUser user){

        boolean userCreated = false;
        final AdminCreateUserRequest adminCreateUserRequest = new AdminCreateUserRequest()
                .withUserPoolId(getAwsCognitoConfig().getPoolId())
                .withUsername(user.getUserName())
                .withMessageAction(MessageActionType.SUPPRESS)
                .withTemporaryPassword(user.getPassword())
                .withUserAttributes(Arrays.asList(
                        new AttributeType().withName("email").withValue(user.getEmail()),
                        new AttributeType().withName("given_name").withValue(user.getFirstName()),
                        new AttributeType().withName("family_name").withValue(user.getLastName()),
                        new AttributeType().withName("phone_number").withValue(user.getPhoneNumber()),
                        new AttributeType().withName("email_verified").withValue("false")
                ));

        AdminCreateUserResult createUserResult;
        try{

            //Cognito Status = FORCE_CHANGE_PASSWORD and No sending of temp password
            createUserResult = getIdentityProvider().adminCreateUser(adminCreateUserRequest);


            if(createUserResult != null){

                Map<String, String> authParams = new HashMap<>();
                authParams.put("USERNAME", user.getUserName());
                authParams.put("PASSWORD", user.getPassword());


                final AdminInitiateAuthRequest adminInitiateAuthRequest = new AdminInitiateAuthRequest()
                        .withClientId(getAwsCognitoConfig().getClientId())
                        .withUserPoolId(getAwsCognitoConfig().getPoolId())
                        .withAuthFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
                        .withAuthParameters(authParams);

                //Cognito Status = NEW_PASSWORD_REQUIRED, Session is found and null AuthenticationResultType
                final AdminInitiateAuthResult authResult = getIdentityProvider().adminInitiateAuth(adminInitiateAuthRequest);

                if(authResult != null && authResult.getSession() != null
                        && ChallengeNameType.NEW_PASSWORD_REQUIRED.name().equals(authResult.getChallengeName())){
                    authParams = new HashMap<>();
                    authParams.put("USERNAME", user.getUserName());
                    authParams.put("NEW_PASSWORD", user.getPassword());


                    final AdminRespondToAuthChallengeRequest respondToAuthChallengeRequest = new AdminRespondToAuthChallengeRequest()
                            .withClientId(getAwsCognitoConfig().getClientId())
                            .withUserPoolId(getAwsCognitoConfig().getPoolId())
                            .withChallengeName(ChallengeNameType.NEW_PASSWORD_REQUIRED)
                            .withSession(authResult.getSession())
                            .withChallengeResponses(authParams);

                    final AdminRespondToAuthChallengeResult respondToAuthChallengeResult = getIdentityProvider().adminRespondToAuthChallenge(respondToAuthChallengeRequest);
                    userCreated = (respondToAuthChallengeResult != null);
                }
            }

        }catch(UsernameExistsException userex){
            throw new AuthException("R3AppAuth::UserAlreadyExist", userex);
        }catch(InvalidParameterException invex){
            throw new AuthException("R3AppAuth::InvalidParameterProvided", invex);
        }catch(CodeDeliveryFailureException codex){
            throw new AuthException("R3AppAuth::CodeDeliveryError", codex);
        }

        final UserType userType = createUserResult.getUser();
        return (userType.isEnabled() && userCreated);

    }


    @Override
    public boolean generateCodeForEmailVerification(String accessToken) {
        final GetUserAttributeVerificationCodeRequest verificationCodeRequest = new GetUserAttributeVerificationCodeRequest()
                .withAccessToken(accessToken)
                .withAttributeName("email");
        GetUserAttributeVerificationCodeResult verificationCodeResult;
        try {
            //Sends an email with a verification code
            verificationCodeResult = getIdentityProvider().getUserAttributeVerificationCode(verificationCodeRequest);
        }catch(InvalidParameterException invex){
            throw new AuthException("R3AppAuth::InvalidParameterProvided", invex);
        }catch(CodeDeliveryFailureException codex){
            throw new AuthException("R3AppAuth::CodeDeliveryError", codex);
        }
        return (verificationCodeResult.getSdkHttpMetadata().getHttpStatusCode() == 200);
    }


    @Override
    public boolean verifyEmailByCode(String accessToken, String code) {
        final VerifyUserAttributeRequest verifyEmailRequest = new VerifyUserAttributeRequest()
                .withAccessToken(accessToken)
                .withAttributeName("email")
                .withCode(code);
        VerifyUserAttributeResult verifyEmailResult;
        try{
            verifyEmailResult = getIdentityProvider().verifyUserAttribute(verifyEmailRequest);
        }catch(InvalidParameterException invex){
            throw new AuthException("R3AppAuth::InvalidParameterProvided", invex);
        }catch(CodeDeliveryFailureException codex){
            throw new AuthException("R3AppAuth::CodeDeliveryError", codex);
        }
        return (verifyEmailResult != null && verifyEmailResult.getSdkHttpMetadata().getHttpStatusCode() == 200);

    }
}
