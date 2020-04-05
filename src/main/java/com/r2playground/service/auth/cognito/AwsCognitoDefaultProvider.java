package com.r2playground.service.auth.cognito;


import com.amazonaws.services.cognitoidp.model.*;
import com.r2playground.service.auth.domain.*;
import com.r2playground.service.auth.exception.AuthException;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Use the Cognito where the username is an email address
 */
public class AwsCognitoDefaultProvider extends AwsCognitoBaseProvider{

    public AwsCognitoDefaultProvider(AwsCognitoCredentials credentials){
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
                .withDesiredDeliveryMediums(DeliveryMediumType.EMAIL)
                .withUserAttributes(Arrays.asList(
                        new AttributeType().withName("email").withValue(user.getEmail()),
                        new AttributeType().withName("given_name").withValue(user.getFirstName()),
                        new AttributeType().withName("family_name").withValue(user.getLastName()),
                        new AttributeType().withName("phone_number").withValue(user.getPhoneNumber()),
                        new AttributeType().withName("email_verified").withValue("true")
                ));

        AdminCreateUserResult createUserResult;
        try{
            createUserResult = getIdentityProvider().adminCreateUser(adminCreateUserRequest);
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

    /**
     * Initiate the login
     * @param username
     * @param password
     * @return
     */
    public AwsCognitoResponse loginUser(String username, String password){

        final Map<String, String> params = new HashMap<>();
        params.put("USERNAME",username);
        params.put("PASSWORD", password);

        final AdminInitiateAuthRequest authRequest = new AdminInitiateAuthRequest()
                .withAuthFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
                .withAuthParameters(params)
                .withClientId(getAwsCognitoConfig().getClientId())
                .withUserPoolId(getAwsCognitoConfig().getPoolId());

        AdminInitiateAuthResult result = null;

        try{
            result = getIdentityProvider().adminInitiateAuth(authRequest);
        }catch(NotAuthorizedException naex){
            throw new AuthException("R3AppAuth::NotAuthorized", naex);
        }catch(PasswordResetRequiredException pwdex){
            throw new AuthException("R3AppAuth::PasswordResetRequired", pwdex);
        }catch(UserNotFoundException unfex){
            throw new AuthException("R3AppAuth::UserNotFound", unfex);
        }catch(UserNotConfirmedException uncex){
            throw new AuthException("R3AppAuth::UserNotConfirmed", uncex);
        }catch(ResourceNotFoundException ex){
            throw new AuthException("R3AppAuth::ResourceNotFound", ex);
        }catch(Exception ex){
            throw new AuthException("R3AppAuth::GenericError", ex);
        }

        if(result == null || result.getAuthenticationResult() == null){
            throw new AuthException("R3AppAuth::NoResponseError", null);
        }

        final AwsCognitoResult response = new AwsCognitoResult(
                result.getSession(),
                result.getAuthenticationResult().getAccessToken(),
                result.getAuthenticationResult().getRefreshToken(),
                AwsResponseType.getType(result.getChallengeName())
        );
        return new AwsCognitoResponse(response, true);
    }

    /**
     * Responds to the authentication challenge put in place the authentication provider. This is called after the user logs in
     * using the temporary password. User, who uses the temporary password to login, must provide a new password.
     *
     * @param username
     * @param newPassword
     * @param challengeSessionId
     */
    public AwsCognitoResponse respondToAuthChallenge(String username, String newPassword, String challengeSessionId){

        Map<String, String> challengeResponse = new HashMap<>();
        challengeResponse.put("USERNAME", username);
        challengeResponse.put("NEW_PASSWORD", newPassword);

        final RespondToAuthChallengeRequest challengeRequest = new RespondToAuthChallengeRequest()
                .withClientId(getAwsCognitoConfig().getClientId())
                .withSession(challengeSessionId)
                .withChallengeName(AwsResponseType.NEW_PASSWORD_REQUIRED.getValue())
                .withChallengeResponses(challengeResponse);

        RespondToAuthChallengeResult challengeResult = null;

        try{
            challengeResult = getIdentityProvider().respondToAuthChallenge(challengeRequest);
        }catch(UserNotFoundException unfex) {
            return new AwsCognitoResponse(new AwsCognitoError(errorCodes.get(USER_NOT_FOUND), USER_NOT_FOUND));
        }catch(InvalidPasswordException invex){
            return new AwsCognitoResponse(new AwsCognitoError(errorCodes.get(INVALID_USER_PASSWORD), INVALID_USER_PASSWORD));
        }catch(Exception ex){
            throw new AuthException("R3AppAuth::GenericError", ex);
        }

        if(challengeResult == null && challengeResult.getAuthenticationResult() == null)   {
            return null;
        }

        final AwsCognitoResult response = new AwsCognitoResult(
                challengeResult.getSession(),
                challengeResult.getAuthenticationResult().getAccessToken(),
                challengeResult.getAuthenticationResult().getRefreshToken(),
                AwsResponseType.getType(challengeResult.getChallengeName())
        );
        return new AwsCognitoResponse(response, true);

    }


    /**
     * Deletes the user details using Admin Role
     * @param username
     */
    public boolean deleteUserDetailByAdmin(String username){
        final AdminDeleteUserRequest request = new AdminDeleteUserRequest().withUsername(username)
                .withUserPoolId(getAwsCognitoConfig().getPoolId());
        final AdminDeleteUserResult result = getIdentityProvider().adminDeleteUser(request);
        return result != null;
    }


    /**
     * Gets the user details using Admin Role
     *
     * @param username
     * @param userAttributes
     * @return
     */
    public UserDetail getUserDetailsByAdmin(String username, List<AwsUserAttributes> userAttributes){
        final AdminGetUserRequest adminRequest = new AdminGetUserRequest()
                .withUsername(username).withUserPoolId(getAwsCognitoConfig().getPoolId());
        final AdminGetUserResult result = getIdentityProvider().adminGetUser(adminRequest);
        UserDetail user = getUserDetails(result.getUserAttributes(), userAttributes);
        return user;
    }



    private UserDetail getUserDetails(List<AttributeType> attributes, List<AwsUserAttributes> userAttributes){
        final UserDetail user = new UserDetail();
        Map<String, String> attributeMaps = null;
        if(userAttributes != null && !userAttributes.isEmpty()){
            attributeMaps = userAttributes.stream().collect(Collectors.toMap(AwsUserAttributes::getName, AwsUserAttributes::getValues));
        }

        final Map<String, String> finalAttributeMaps = attributeMaps;
        final List<AwsUserAttributes> attributesList = new ArrayList<>();
        attributes.stream().forEach(attr -> {

            if("email".equals(attr.getName())){
                user.setEmail(attr.getValue());
            }else if("given_name".equals(attr.getName())){
                user.setFirstName(attr.getValue());
            }else if("family_name".equals(attr.getName())){
                user.setLastName(attr.getValue());
            }else if("phone_number".equals(attr.getName())){
                user.setPhoneNumber(attr.getValue());
            }else{
                if(finalAttributeMaps.containsKey(attr.getName())){
                    attributesList.add(new AwsUserAttributes(attr.getName(), attr.getValue()));
                }
            }
        });
        if(!attributesList.isEmpty()){
            user.setAttributes(attributesList);
        }
        return user;
    }


    /**
     * Gets the user details stored in the provider
     *
     * @param accessToken - token provided by the provider
     * @param userAttributes
     */
    public AwsUser getUserDetails(String accessToken,  List<AwsUserAttributes> userAttributes){
        final GetUserRequest userRequest = new GetUserRequest().withAccessToken(accessToken);
        GetUserResult userResult = null;
        try {
            userResult = getIdentityProvider().getUser(userRequest);

        }catch(NotAuthorizedException ex){
            throw new AuthException("R3AppAuth::NotAUthorized", ex);
        }catch(PasswordResetRequiredException ex){
            throw new AuthException("R3AppAuth::PasswordReset", ex);
        }catch(ResourceNotFoundException ex){
            throw new AuthException("R3AppAuth::ResourceNotFound", ex);
        }catch(InvalidParameterException ex){
            throw new AuthException("R3AppAuth::InvalidParam", ex);
        }catch(InternalErrorException ex){
            throw new AuthException("R3AppAuth::InternalError", ex);
        }catch(Exception ex){
            throw new AuthException("R3AppAuth::GenericError", ex);
        }

        return getUserDetails(userResult.getUserAttributes(), userAttributes);

    }

    /**
     * Request a change of password for a given user with the accesstoken
     * @param accessToken
     * @param oldPassword
     * @param newPassword
     * @param traceId
     */
    public AwsCognitoResponse changePassword(String accessToken, String oldPassword, String newPassword, String traceId){
        final ChangePasswordRequest request = new ChangePasswordRequest()
                .withAccessToken(accessToken)
                .withPreviousPassword(oldPassword)
                .withProposedPassword(newPassword);
        ChangePasswordResult result;
        try{
            result = getIdentityProvider().changePassword(request);
        }catch(InvalidPasswordException ex) {
            return new AwsCognitoResponse(new AwsCognitoError(errorCodes.get(INVALID_USER_PASSWORD), INVALID_USER_PASSWORD));
        }catch(NotAuthorizedException ex) {
            throw new AuthException("R3AppAuth::NotAuthorized", ex);
        }catch(PasswordResetRequiredException ex) {
            return new AwsCognitoResponse(new AwsCognitoError(errorCodes.get(PASSWORD_RESET_REQUIRED), PASSWORD_RESET_REQUIRED));
        }catch(InvalidParameterException ex) {
            throw new AuthException("R3AppAuth::InvalidParameter", ex);
        }catch(Exception ex){
            throw new AuthException("R3AppAuth::GenericError", ex);
        }
        return new AwsCognitoResponse(null, result != null);
    }

    /**
     * Invoke a forgotten password for a given username. If the user is still using the temp password and requesting for this flow
     * then provider will throw a NotAuthorizedException
     *
     * @param username
     *
     */
    public AwsCognitoResponse forgotPassword(String username){
        final ForgotPasswordRequest forgotPasswordRequest = new ForgotPasswordRequest()
                .withClientId(getAwsCognitoConfig().getClientId())
                .withUsername(username);

        ForgotPasswordResult result = null;
        try{
            result = getIdentityProvider().forgotPassword(forgotPasswordRequest);
        }catch(CodeDeliveryFailureException ex){
            throw new AuthException("R3AppAuth::CodeDelivery", ex);
        }catch(UserNotFoundException ex){
            return new AwsCognitoResponse(new AwsCognitoError(errorCodes.get(USER_NOT_FOUND), USER_NOT_FOUND));
        }catch (NotAuthorizedException ex) {
            throw new AuthException("R3AppAuth::NotAUthorized", ex);
        }catch(LimitExceededException ex){
            throw new AuthException("R3AppAuth::LimitExceedException", ex);
        }catch(Exception ex){
            throw new AuthException("R3AppAuth::GenericError", ex);
        }
        return new AwsCognitoResponse(null, result != null);
    }


}
