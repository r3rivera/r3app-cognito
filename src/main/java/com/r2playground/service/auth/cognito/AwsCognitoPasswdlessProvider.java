package com.r2playground.service.auth.cognito;

import com.amazonaws.services.cognitoidp.model.AdminCreateUserRequest;
import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthRequest;
import com.amazonaws.services.cognitoidp.model.AttributeType;
import com.amazonaws.services.cognitoidp.model.DeliveryMediumType;
import com.r2playground.service.auth.domain.AwsUser;

import java.util.Arrays;

public class AwsCognitoPasswdlessProvider extends AwsCognitoBaseProvider {

    public AwsCognitoPasswdlessProvider(AwsCognitoCredentials credentials){
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

        return false;

    }
}
