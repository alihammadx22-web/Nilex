# Google OAuth local login

NILEX uses Google's OpenID Connect authorization-code flow. Spring Security validates Google's ID token, then NILEX issues its own access and refresh tokens. Google tokens are not used as NILEX API credentials.

## Google Cloud setup

1. Configure the OAuth consent screen in Google Cloud. If the app is in testing mode, add the Google accounts that will test it as test users.
2. Create an OAuth client of type **Web application**. Add this exact authorized redirect URI: `http://localhost:8080/login/oauth2/code/google`.
3. In the project's root-level, Git-ignored `application-local.properties`, add these two keys using the Web application client's values:

   ```properties
   google.oauth.client-id=<web-client-id>
   google.oauth.client-secret=<web-client-secret>
   ```

   Keep the values in that local file. Do not paste them into chat, commit them, or put them in source-controlled configuration.

## Test in a browser

Run the Spring Boot application on port 8080 and visit `http://localhost:8080/oauth2/authorization/google`. After Google sign-in and consent, the callback returns a JSON response containing the existing NILEX token pair and user summary. Tokens are in the response body, never in a URL. The response has `Cache-Control: no-store`, and the short-lived OAuth session is invalidated. Do not copy tokens into browser URLs or share the response.

The same NILEX `POST /api/v1/auth/refresh` and `POST /api/v1/auth/logout` endpoints work with these tokens. A Google identity whose email already belongs to an unlinked NILEX account is rejected; matching email is not enough to link accounts. Explicit account linking can be added later with a separate, authenticated flow.

If either Google credential key is absent, the Google browser flow is disabled while existing password login remains available.
