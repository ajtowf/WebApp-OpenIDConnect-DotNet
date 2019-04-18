## Overview

This sample implements an authentication flow where a user signs into a MVC application which then is accessing a secure web service. That web service will then act on behalf of the authenticated user to get an access token and access another secure web service.

![alt text](https://github.com/ajtowf/WebApp-OpenIDConnect-DotNet/raw/master/ReadmeFiles/overview.png "Architecture overview")

Below is the authentication flow that the sample will achieve

 1. Client authenticates to AD FS authorization end point and requests an authorization code
 2. Authorization endpoint returns authentication code to client
 3. Client uses authentication code and presents it to the AD FS token endpoint to request access token for the Secure WebAPI
 4. AD FS returns the access token to Secure WebAPI. For additional functionality, Secure WebAPI needs access to the Other Secure WebAPI
 5. Client uses the access token to use Secure WebAPI service.
 6. Secure WebAPI service provides the access token to the AD FS token end point and requests access token for Other Secure WebAPI on-behalf-of the authenticated user
 7. AD FS returns access token for Other Secure WebAPI to Secure WebAPI acting as client
 8. Secure WebAPI uses the access token provided by AD FS in step 7 to access the Other Secure WebAPI as client and perform the necessary functions