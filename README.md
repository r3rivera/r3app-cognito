# r3app-cognito
Different implementation of user registration using AWS Cognito

Uses Cognito User Pool with the email as the username. Standard attributes.

1. AwsCognitoDefaultProvider - This class uses the following registration steps:
   1.1 User signs-up/registers providing the email address as the username, firstname, lastname and phone number as attributes. Cognito responds by sending a temporary password in the email provided. 
   1.2 User logs in using the temporary password and is required to provide their own password. Cognito confirms the user (account status is CONFIRMED) and verifies the email of the user. 
   

2. AwsCognitoUserPasswordProvider - This class uses the following registration steps:
   2.1 User signs-up/registers providing the email address as the username, firstname, lastname and phone number and their own password. Cognito set the account status of the user to CONFIRMED but with non-verified email.  
   
