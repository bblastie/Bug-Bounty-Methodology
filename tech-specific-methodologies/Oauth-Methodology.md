# Oauth Hacking Methodology 

References: 
- https://portswigger.net/web-security/oauth 
- https://0xn3va.gitbook.io/cheat-sheets/web-application/oauth-2.0-vulnerabilities

## Recon
- Review Oauth service providers available
    - Google, Facebook, Apple, etc.
- Pick a provider and perform a full flow authentication for the first time
- Make note of requests, particularly requests to the service provider that includes things like redirect URI 

      `GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=token&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1` 
- Determine the OAuth grant type (Implicit vs. Authorization code)
    - https://portswigger.net/web-security/oauth/grant-types 

## Session fixation
- Login to application and take note of how the session is being stored (bearer token or cookie)
- Take note of the bearer token or cookie value
- log out of the application
- Send HTTP requests with the token or cookie value to the application
- If the application accepts the token or cookie value, then the application is vulnerable to session fixation

## Redirect URI not validated
#### Test for redirect to arbitrary domain in param `redirect_uri`
- If you are able to use an arbitrary domain in `redirect-uri`, setup an attacker controlled domain and perform an authentication with the `redirect-uri` populated with the attacker domain
    - If the victim is already logged into the service provider, they will be redirected to the attacker domain with the `code` param in the URL
    - server side code can be used to capture the `code` param and then use it to perform a token exchange

#### Test for redirect to another page via param `redirect-uri` but using directory traversal 
- https://portswigger.net/web-security/oauth#leaking-authorization-codes-and-access-tokens 
- If you are only able to redirect to another page of the Service Provider via directory traversal:
    - Try to find an open redirect bug on the application
    - Change the redirect URI to the page with the open redirect
    - Chain the open redirect to leak the code 
    - https://salt.security/blog/traveling-with-oauth-account-takeover-on-booking-com

## Broken `State` Parameter CSRF
- If the `state` parameter is not validated, it can be used to perform CSRF attacks
    - https://book.hacktricks.xyz/pentesting-web/oauth-to-account-takeover/oauth-happy-paths-xss-iframes-and-post-messages-to-leak-code-and-state-values#break-state-intentionally
### Test for state param issues
#### Improper validation 
- Generate a state param value via authentication with user 1
- Use that state param in the auth flow of user 2
- If the application allows the auth flow to complete, then the application is vulnerable to broken state parameter CSRF

#### No Validation
- Intercept the auth request and remove the state param
- If the application allows the auth flow to complete, then the application is vulnerable to broken state parameter CSRF

### Broken State Attack Flow
- Attacker generates `state` param by completing an auth
- Attacker sends a link to the victim with the `state` param populated with the attacker generated value
- Victim tries to sign in via the attacker crafted URL (think iframe embedded on a malicious site)
- Website validates the state for the victim and stops processing the sign-in flow since it’s not a valid state. Error page for victim.
- Attacker finds a way to leak the code from the error page.
- Attacker can now sign in with their own state and the code leaked from the victim. 

## If using AWS cognito as the Oauth provider
- https://medium.com/p/36a209a0bd8a
- https://security.lauritz-holtmann.de/advisories/flickr-account-takeover/#amazon-cognito 
- https://blog.appsecco.com/exploiting-weak-configurations-in-amazon-cognito-in-aws-471ce761963 
- https://www.yassineaboukir.com/talks/NahamConEU2022.pdf

