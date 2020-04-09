package com.r2playground.service.auth.cognito;

import com.amazonaws.services.cognitoidp.model.*;
import com.r2playground.service.auth.domain.AwsCognitoResponse;
import com.r2playground.service.auth.domain.AwsUser;
import com.r2playground.service.auth.domain.AwsUserAttributes;
import com.r2playground.service.auth.domain.UserDetail;
import com.r2playground.service.auth.exception.AuthException;

import java.util.Arrays;
import java.util.List;

public class AwsCognitoUserPasswordProvider extends AwsCognitoBaseProvider implements AwsCognitoProvider{

    public AwsCognitoUserPasswordProvider(AwsCognitoCredentials credentials){
        super(credentials);
    }

    /**
     * Creates a new user within Cognito
     * @param user
     * @return
     */
    public boolean createUser(AwsUser user){

        final AdminCreateUserRequest adminCreateUserRequest = new AdminCreateUserRequest()
                .withUserPoolId(getAwsCognitoConfig().getPoolId())
                .withUsername(user.getUserName())
                .withMessageAction(MessageActionType.SUPPRESS)
                .withTemporaryPassword(user.getPassword())
                .withUserAttributes(Arrays.asList(
                        new AttributeType().withName("email").withValue(user.getEmail()),
                        new AttributeType().withName("given_name").withValue(user.getFirstName()),
                        new AttributeType().withName("family_name").withValue(user.getLastName()),
                        new AttributeType().withName("phone_number").withValue(user.getPhoneNumber())
                ));

        AdminCreateUserResult createUserResult;
        try{
            createUserResult = getIdentityProvider().adminCreateUser(adminCreateUserRequest);

            if(createUserResult != null){

            }

        }catch(UsernameExistsException userex){
            throw new AuthException("R3AppAuth::UserAlreadyExist", userex);
        }catch(InvalidParameterException invex){
            throw new AuthException("R3AppAuth::InvalidParameterProvided", invex);
        }catch(CodeDeliveryFailureException codex){
            throw new AuthException("R3AppAuth::CodeDeliveryError", codex);
        }

        final UserType userType = createUserResult.getUser();
        return userType.isEnabled();

    }

    @Override
    public AwsCognitoResponse loginUser(String username, String password) {
        return null;
    }

    @Override
    public AwsCognitoResponse respondToAuthChallenge(String username, String newPassword, String challengeSessionId) {
        return null;
    }

    @Override
    public boolean deleteUserDetailByAdmin(String username) {
        return false;
    }

    @Override
    public UserDetail getUserDetailsByAdmin(String username, List<AwsUserAttributes> userAttributes) {
        return null;
    }

    @Override
    public AwsUser getUserDetails(String accessToken, List<AwsUserAttributes> userAttributes) {
        return null;
    }

    @Override
    public AwsCognitoResponse changePassword(String accessToken, String oldPassword, String newPassword) {
        return null;
    }

    @Override
    public AwsCognitoResponse forgotPassword(String username) {
        return null;
    }

    @Override
    public AwsCognitoResponse confirmForgotPassword(String username, String newPassword, String confirmationCode) {
        return null;
    }

    @Override
    public AwsCognitoResponse resendTempPassword(String username) {
        return null;
    }
}
