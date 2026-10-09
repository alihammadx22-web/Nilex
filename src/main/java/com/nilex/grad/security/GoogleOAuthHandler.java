package com.nilex.grad.security;

import com.nilex.grad.exception.ApiError;
import com.nilex.grad.exception.GoogleAccountConflictException;
import com.nilex.grad.exception.InvalidCredentialsException;
import com.nilex.grad.service.GoogleLoginService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;

@Component
@RequiredArgsConstructor
@ConditionalOnProperty(prefix = "google.oauth", name = {"client-id", "client-secret"})
public class GoogleOAuthHandler implements AuthenticationSuccessHandler, AuthenticationFailureHandler {

    private final GoogleLoginService googleLoginService;
    private final ClientRegistrationRepository clientRegistrations;
    private final OAuth2AuthorizedClientService authorizedClients;
    private final ObjectMapper objectMapper;

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) throws IOException {
        Object body;
        int status;
        try {
            if (!(authentication instanceof OAuth2AuthenticationToken oauth)
                    || !"google".equals(oauth.getAuthorizedClientRegistrationId())
                    || !(oauth.getPrincipal() instanceof OidcUser identity)) {
                throw new InvalidCredentialsException();
            }
            String clientId = clientRegistrations.findByRegistrationId("google").getClientId();
            body = googleLoginService.login(identity, clientId);
            status = HttpServletResponse.SC_OK;
        } catch (GoogleAccountConflictException exception) {
            status = HttpServletResponse.SC_CONFLICT;
            body = ApiError.of(
                    HttpServletResponse.SC_CONFLICT,
                    "GOOGLE_ACCOUNT_CONFLICT",
                    exception.getMessage()
            );
        } catch (InvalidCredentialsException exception) {
            status = HttpServletResponse.SC_UNAUTHORIZED;
            body = unauthorizedError();
        } finally {
            if (authentication instanceof OAuth2AuthenticationToken oauth) {
                authorizedClients.removeAuthorizedClient(
                        oauth.getAuthorizedClientRegistrationId(),
                        oauth.getName()
                );
            }
            clearBrowserSession(request);
        }
        writeJson(response, status, body);
    }

    @Override
    public void onAuthenticationFailure(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException exception
    ) throws IOException {
        clearBrowserSession(request);
        writeUnauthorized(response);
    }

    private void writeUnauthorized(HttpServletResponse response) throws IOException {
        writeJson(response, HttpServletResponse.SC_UNAUTHORIZED, unauthorizedError());
    }

    private static ApiError unauthorizedError() {
        return ApiError.of(
                HttpServletResponse.SC_UNAUTHORIZED,
                "UNAUTHORIZED",
                RestAuthenticationEntryPoint.MESSAGE
        );
    }

    private void writeJson(HttpServletResponse response, int status, Object body) throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Referrer-Policy", "no-referrer");
        objectMapper.writeValue(response.getOutputStream(), body);
    }

    private static void clearBrowserSession(HttpServletRequest request) {
        SecurityContextHolder.clearContext();
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
    }
}
