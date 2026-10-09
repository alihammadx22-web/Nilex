package com.nilex.grad.service;

import com.nilex.grad.dto.LoginRequest;
import com.nilex.grad.dto.LoginResponse;
import com.nilex.grad.exception.InvalidCredentialsException;

import com.nilex.grad.security.JwtAccessTokenService;
import com.nilex.grad.security.IssuedAccessToken;
import com.nilex.grad.dto.SessionCredentials;
import com.nilex.grad.model.User;
import com.nilex.grad.repository.UserRepository;
import com.nilex.grad.model.UserRole;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LoginServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private JwtAccessTokenService accessTokenService;

    @Mock
    private SessionService sessionService;

    private BCryptPasswordEncoder passwordEncoder;
    private LoginService loginService;

    @BeforeEach
    void setUp() {
        passwordEncoder = new BCryptPasswordEncoder();
        loginService = new LoginService(
                userRepository,
                passwordEncoder,
                accessTokenService,
                sessionService
        );
    }

    @Test
    void logsInCaseInsensitivelyAndPreservesAdminRole() {
        UUID userId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);
        when(user.getName()).thenReturn("Nilex Admin");
        when(user.getEmail()).thenReturn("admin@example.com");
        when(user.getPasswordHash()).thenReturn(passwordEncoder.encode("correct-horse"));
        when(user.getRole()).thenReturn(UserRole.ADMIN);
        when(user.isActive()).thenReturn(true);
        when(userRepository.findByEmailIgnoreCase("admin@example.com")).thenReturn(Optional.of(user));
        UUID sessionId = UUID.randomUUID();
        when(sessionService.start(user)).thenReturn(new SessionCredentials(
                sessionId,
                user,
                "refresh-token",
                2_592_000,
                Instant.parse("2026-01-31T00:00:00Z")
        ));
        when(accessTokenService.issueFor(user, sessionId)).thenReturn(new IssuedAccessToken(
                "token",
                1_800,
                Instant.parse("2026-01-01T00:30:00Z")
        ));

        LoginResponse response = loginService.login(new LoginRequest(
                "  ADMIN@Example.COM  ",
                "correct-horse"
        ));

        assertThat(response.user().id()).isEqualTo(userId);
        assertThat(response.user().role()).isEqualTo(UserRole.ADMIN);
        assertThat(response.expiresIn()).isEqualTo(1_800);
        assertThat(response.refreshExpiresIn()).isEqualTo(2_592_000);
        verify(userRepository).findByEmailIgnoreCase("admin@example.com");
    }

    @Test
    void rejectsWrongPasswordWithoutIssuingAToken() {
        User user = mock(User.class);
        when(user.getPasswordHash()).thenReturn(passwordEncoder.encode("correct-horse"));
        when(userRepository.findByEmailIgnoreCase("person@example.com")).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> loginService.login(new LoginRequest(
                "person@example.com",
                "wrong-password"
        ))).isInstanceOf(InvalidCredentialsException.class);

        verify(sessionService, never()).start(user);
    }

    @Test
    void rejectsUnknownEmailWithTheSameError() {
        when(userRepository.findByEmailIgnoreCase("missing@example.com")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> loginService.login(new LoginRequest(
                "missing@example.com",
                "wrong-password"
        ))).isInstanceOf(InvalidCredentialsException.class)
                .hasMessage("Authentication is required or the supplied credentials are invalid");

        verify(sessionService, never()).start(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void googleOnlyAccountCannotUsePasswordLogin() {
        User user = mock(User.class);
        when(user.getPasswordHash()).thenReturn(null);
        when(userRepository.findByEmailIgnoreCase("google@example.com")).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> loginService.login(new LoginRequest(
                "google@example.com",
                "nilex-dummy-password"
        ))).isInstanceOf(InvalidCredentialsException.class);

        verify(sessionService, never()).start(user);
    }
}
