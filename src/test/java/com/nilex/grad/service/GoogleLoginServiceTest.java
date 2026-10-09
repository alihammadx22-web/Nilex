package com.nilex.grad.service;

import com.nilex.grad.dto.SessionCredentials;
import com.nilex.grad.exception.GoogleAccountConflictException;
import com.nilex.grad.exception.InvalidCredentialsException;
import com.nilex.grad.model.User;
import com.nilex.grad.model.UserRole;
import com.nilex.grad.repository.UserRepository;
import com.nilex.grad.security.IssuedAccessToken;
import com.nilex.grad.security.JwtAccessTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GoogleLoginServiceTest {

    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");
    private static final String CLIENT_ID = "local-test-client";

    @Mock
    private UserRepository userRepository;

    @Mock
    private SessionService sessionService;

    @Mock
    private JwtAccessTokenService accessTokenService;

    private GoogleLoginService service;

    @BeforeEach
    void setUp() {
        service = new GoogleLoginService(
                userRepository,
                sessionService,
                accessTokenService,
                Clock.fixed(NOW, ZoneOffset.UTC)
        );
    }

    @Test
    void createsUserRoleWithoutPasswordAndIssuesExistingSessionTokens() {
        User saved = user();
        when(userRepository.findByGoogleSubject("google-subject")).thenReturn(Optional.empty());
        when(userRepository.saveAndFlush(any(User.class))).thenReturn(saved);
        stubTokens(saved);

        var response = service.login(identity(Map.of()), CLIENT_ID);

        ArgumentCaptor<User> created = ArgumentCaptor.forClass(User.class);
        verify(userRepository).saveAndFlush(created.capture());
        assertThat(created.getValue().getGoogleSubject()).isEqualTo("google-subject");
        assertThat(created.getValue().getPasswordHash()).isNull();
        assertThat(created.getValue().getRole()).isEqualTo(UserRole.USER);
        assertThat(created.getValue().getEmail()).isEqualTo("person@example.com");
        assertThat(response.expiresIn()).isEqualTo(1_800);
        assertThat(response.refreshExpiresIn()).isEqualTo(2_592_000);
        assertThat(response.user().role()).isEqualTo(UserRole.USER);
    }

    @Test
    void reusesUserByStableGoogleSubjectWithoutCreatingAnotherAccount() {
        User existing = user();
        when(userRepository.findByGoogleSubject("google-subject")).thenReturn(Optional.of(existing));
        stubTokens(existing);

        service.login(identity(Map.of()), CLIENT_ID);

        verify(userRepository, never()).saveAndFlush(any(User.class));
        verify(sessionService).start(existing);
    }

    @Test
    void refusesAutomaticEmailBasedLinking() {
        when(userRepository.findByGoogleSubject("google-subject")).thenReturn(Optional.empty());
        when(userRepository.existsByEmailIgnoreCase("person@example.com")).thenReturn(true);

        assertThatThrownBy(() -> service.login(identity(Map.of()), CLIENT_ID))
                .isInstanceOf(GoogleAccountConflictException.class);
        verify(sessionService, never()).start(any(User.class));
    }

    @Test
    void rejectsUnverifiedEmailAndInvalidIssuerOrAudience() {
        assertRejected(Map.of("email_verified", false));
        assertRejected(Map.of("iss", "https://untrusted.example"));
        assertRejected(Map.of("aud", List.of("other-client")));
    }

    @Test
    void rejectsChangedEmailOrInactiveLinkedAccount() {
        User linked = user();
        when(userRepository.findByGoogleSubject("google-subject")).thenReturn(Optional.of(linked));

        assertThatThrownBy(() -> service.login(
                identity(Map.of("email", "different@example.com")), CLIENT_ID))
                .isInstanceOf(InvalidCredentialsException.class);

        when(linked.isActive()).thenReturn(false);
        assertThatThrownBy(() -> service.login(identity(Map.of()), CLIENT_ID))
                .isInstanceOf(InvalidCredentialsException.class);
        verify(sessionService, never()).start(any(User.class));
    }

    private void assertRejected(Map<String, Object> claims) {
        assertThatThrownBy(() -> service.login(identity(claims), CLIENT_ID))
                .isInstanceOf(InvalidCredentialsException.class);
        verify(sessionService, never()).start(any(User.class));
    }

    private OidcUser identity(Map<String, Object> overrides) {
        Map<String, Object> claims = new HashMap<>(Map.of(
                "iss", "https://accounts.google.com",
                "aud", List.of(CLIENT_ID),
                "sub", "google-subject",
                "email", "PERSON@example.com",
                "email_verified", true,
                "name", "Google Person"
        ));
        claims.putAll(overrides);
        OidcIdToken token = new OidcIdToken("test-id-token", NOW, NOW.plus(Duration.ofMinutes(5)), claims);
        OidcUser identity = mock(OidcUser.class);
        when(identity.getIdToken()).thenReturn(token);
        return identity;
    }

    private User user() {
        User user = mock(User.class);
        when(user.getEmail()).thenReturn("person@example.com");
        when(user.isActive()).thenReturn(true);
        return user;
    }

    private void stubTokens(User user) {
        UUID sessionId = UUID.randomUUID();
        when(user.getId()).thenReturn(UUID.randomUUID());
        when(user.getName()).thenReturn("Google Person");
        when(user.getRole()).thenReturn(UserRole.USER);
        when(sessionService.start(user)).thenReturn(new SessionCredentials(
                sessionId, user, "refresh-token", 2_592_000, NOW.plus(Duration.ofDays(30))
        ));
        when(accessTokenService.issueFor(user, sessionId)).thenReturn(new IssuedAccessToken(
                "access-token", 1_800, NOW.plus(Duration.ofMinutes(30))
        ));
    }
}
