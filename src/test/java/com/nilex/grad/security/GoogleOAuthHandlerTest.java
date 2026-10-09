package com.nilex.grad.security;

import com.nilex.grad.dto.AuthenticatedUserResponse;
import com.nilex.grad.dto.LoginResponse;
import com.nilex.grad.exception.GoogleAccountConflictException;
import com.nilex.grad.model.UserRole;
import com.nilex.grad.service.GoogleLoginService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import tools.jackson.databind.ObjectMapper;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GoogleOAuthHandlerTest {

    @Mock
    private GoogleLoginService googleLoginService;

    @Mock
    private ClientRegistrationRepository clientRegistrations;

    @Mock
    private OAuth2AuthorizedClientService authorizedClients;

    private GoogleOAuthHandler handler;

    @BeforeEach
    void setUp() {
        handler = new GoogleOAuthHandler(
                googleLoginService,
                clientRegistrations,
                authorizedClients,
                new ObjectMapper()
        );
    }

    @Test
    void successReturnsUncachedJsonTokensWithoutRedirectAndClearsOAuthSession() throws Exception {
        OidcUser identity = mock(OidcUser.class);
        when(identity.getName()).thenReturn("google-subject");
        OAuth2AuthenticationToken authentication =
                new OAuth2AuthenticationToken(identity, List.of(), "google");
        ClientRegistration registration = mock(ClientRegistration.class);
        when(registration.getClientId()).thenReturn("test-client");
        when(clientRegistrations.findByRegistrationId("google")).thenReturn(registration);
        when(googleLoginService.login(identity, "test-client")).thenReturn(tokens());
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = (MockHttpSession) request.getSession(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(request, response, authentication);

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getContentType()).startsWith("application/json");
        assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
        assertThat(response.getHeader("Location")).isNull();
        assertThat(response.getContentAsString()).contains("access-token", "refresh-token");
        assertThat(session.isInvalid()).isTrue();
        verify(authorizedClients).removeAuthorizedClient("google", "google-subject");
    }

    @Test
    void existingEmailConflictReturnsSafeErrorWithoutTokens() throws Exception {
        OidcUser identity = mock(OidcUser.class);
        when(identity.getName()).thenReturn("google-subject");
        OAuth2AuthenticationToken authentication =
                new OAuth2AuthenticationToken(identity, List.of(), "google");
        ClientRegistration registration = mock(ClientRegistration.class);
        when(registration.getClientId()).thenReturn("test-client");
        when(clientRegistrations.findByRegistrationId("google")).thenReturn(registration);
        when(googleLoginService.login(identity, "test-client"))
                .thenThrow(new GoogleAccountConflictException());
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(new MockHttpServletRequest(), response, authentication);

        assertThat(response.getStatus()).isEqualTo(409);
        assertThat(response.getContentAsString()).contains("GOOGLE_ACCOUNT_CONFLICT");
        assertThat(response.getContentAsString()).doesNotContain("accessToken", "refreshToken");
    }

    @Test
    void providerFailureReturnsGenericUnauthorizedResponse() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationFailure(
                new MockHttpServletRequest(),
                response,
                new BadCredentialsException("provider-specific-details")
        );

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getContentAsString()).contains("UNAUTHORIZED");
        assertThat(response.getContentAsString()).doesNotContain("provider-specific-details");
        assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
    }

    private static LoginResponse tokens() {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        return new LoginResponse(
                "access-token", "Bearer", 1_800, now.plusSeconds(1_800),
                "refresh-token", 2_592_000, now.plusSeconds(2_592_000),
                new AuthenticatedUserResponse(UUID.randomUUID(), "Google User", "user@example.com", UserRole.USER)
        );
    }
}
