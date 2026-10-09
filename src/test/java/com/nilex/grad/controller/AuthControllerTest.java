package com.nilex.grad.controller;

import com.nilex.grad.dto.AuthenticatedUserResponse;
import com.nilex.grad.dto.LoginResponse;
import com.nilex.grad.dto.RefreshResponse;
import com.nilex.grad.dto.RegisterResponse;
import com.nilex.grad.exception.EmailAlreadyRegisteredException;
import com.nilex.grad.exception.InvalidCredentialsException;
import com.nilex.grad.service.LoginService;
import com.nilex.grad.service.RefreshService;
import com.nilex.grad.service.RegistrationService;

import com.nilex.grad.exception.GlobalExceptionHandler;
import com.nilex.grad.config.SecurityConfig;
import com.nilex.grad.service.SessionService;
import com.nilex.grad.model.UserRole;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.time.Instant;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthController.class)
@Import({SecurityConfig.class, GlobalExceptionHandler.class})
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private RegistrationService registrationService;

    @MockitoBean
    private LoginService loginService;

    @MockitoBean
    private RefreshService refreshService;

    @MockitoBean
    private SessionService sessionService;

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @Test
    void registrationIsPublicAndReturnsOnlySafeFields() throws Exception {
        UUID id = UUID.randomUUID();
        when(registrationService.register(any())).thenReturn(new RegisterResponse(
                id,
                "Nilex Person",
                "person@example.com",
                UserRole.USER,
                true,
                Instant.parse("2026-01-01T00:00:00Z")
        ));

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "name": "Nilex Person",
                                  "email": "person@example.com",
                                  "password": "correct-horse"
                                }
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(id.toString()))
                .andExpect(jsonPath("$.role").value("USER"))
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.passwordHash").doesNotExist());
    }

    @Test
    void rejectsPasswordsShorterThanEightCharacters() throws Exception {
        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "name": "Nilex Person",
                                  "email": "person@example.com",
                                  "password": "short"
                                }
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("VALIDATION_FAILED"))
                .andExpect(jsonPath("$.fieldErrors.password").exists());

        verify(registrationService, never()).register(any());
    }

    @Test
    void rejectsClientSuppliedRole() throws Exception {
        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "name": "Nilex Person",
                                  "email": "person@example.com",
                                  "password": "correct-horse",
                                  "role": "ADMIN"
                                }
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("MALFORMED_REQUEST"));

        verify(registrationService, never()).register(any());
    }

    @Test
    void mapsDuplicateEmailToConflictWithoutEchoingTheEmail() throws Exception {
        when(registrationService.register(any())).thenThrow(new EmailAlreadyRegisteredException());

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "name": "Nilex Person",
                                  "email": "person@example.com",
                                  "password": "correct-horse"
                                }
                                """))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("EMAIL_ALREADY_REGISTERED"))
                .andExpect(jsonPath("$.message").value("An account with this email already exists"));
    }

    @Test
    void allOtherEndpointsRequireAuthentication() throws Exception {
        mockMvc.perform(get("/api/v1/not-public"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void loginIsPublicAndReturnsAThirtyMinuteBearerToken() throws Exception {
        UUID id = UUID.randomUUID();
        when(loginService.login(any())).thenReturn(new LoginResponse(
                "header.payload.signature",
                "Bearer",
                1_800,
                Instant.parse("2026-01-01T00:30:00Z"),
                "refresh-token",
                2_592_000,
                Instant.parse("2026-01-31T00:00:00Z"),
                new AuthenticatedUserResponse(id, "Nilex Person", "person@example.com", UserRole.USER)
        ));

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "email": "person@example.com",
                                  "password": "correct-horse"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("header.payload.signature"))
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(1_800))
                .andExpect(jsonPath("$.refreshExpiresIn").value(2_592_000))
                .andExpect(jsonPath("$.user.role").value("USER"))
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.user.passwordHash").doesNotExist());
    }

    @Test
    void invalidLoginReturnsTheStandardUnauthorizedResponse() throws Exception {
        when(loginService.login(any())).thenThrow(new InvalidCredentialsException());

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "email": "person@example.com",
                                  "password": "wrong-password"
                                }
                                """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHORIZED"))
                .andExpect(jsonPath("$.message").value(
                        "Authentication is required or the supplied credentials are invalid"));
    }

    @Test
    void refreshIsPublicAndReturnsRotatedTokens() throws Exception {
        when(refreshService.refresh(any())).thenReturn(new RefreshResponse(
                "new-access-token",
                "Bearer",
                1_800,
                Instant.parse("2026-01-01T00:30:00Z"),
                "new-refresh-token",
                2_592_000,
                Instant.parse("2026-01-31T00:00:00Z")
        ));

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"refreshToken":"old-refresh-token"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("new-access-token"))
                .andExpect(jsonPath("$.refreshToken").value("new-refresh-token"))
                .andExpect(jsonPath("$.refreshExpiresIn").value(2_592_000));
    }

    @Test
    void invalidRefreshReturnsTheStandardUnauthorizedResponse() throws Exception {
        when(refreshService.refresh(any())).thenThrow(new InvalidCredentialsException());

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"refreshToken":"invalid-refresh-token"}
                                """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
    }

    @Test
    void logoutRequiresAnAccessToken() throws Exception {
        mockMvc.perform(post("/api/v1/auth/logout"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
    }
}
