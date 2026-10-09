package com.nilex.grad.controller;

import com.jayway.jsonpath.JsonPath;
import com.nilex.grad.dto.LoginResponse;
import com.nilex.grad.model.UserRole;
import com.nilex.grad.repository.UserRepository;
import com.nilex.grad.service.GoogleLoginService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.test.annotation.Rollback;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
@Rollback
class GoogleAuthenticationDatabaseIntegrationTest {

    private static final String CLIENT_ID = "test-google-client";

    @Autowired
    private GoogleLoginService googleLoginService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private MockMvc mockMvc;

    @Test
    void googleUserReusesNilexRefreshRotationAndSingleDeviceRevocation() throws Exception {
        String suffix = UUID.randomUUID().toString();
        String subject = "google-" + suffix;
        String email = "google-" + suffix + "@example.invalid";
        OidcUser identity = identity(subject, email);

        LoginResponse first = googleLoginService.login(identity, CLIENT_ID);
        var stored = userRepository.findByGoogleSubject(subject).orElseThrow();
        assertThat(stored.getPasswordHash()).isNull();
        assertThat(stored.getRole()).isEqualTo(UserRole.USER);
        assertThat(first.user().id()).isEqualTo(stored.getId());

        mockMvc.perform(get("/api/v1/users/me")
                        .header(HttpHeaders.AUTHORIZATION, bearer(first.accessToken())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(email));

        LoginResponse second = googleLoginService.login(identity, CLIENT_ID);
        assertThat(second.user().id()).isEqualTo(first.user().id());
        assertThat(userRepository.findByEmailIgnoreCase(email)).isPresent();

        mockMvc.perform(get("/api/v1/users/me")
                        .header(HttpHeaders.AUTHORIZATION, bearer(first.accessToken())))
                .andExpect(status().isUnauthorized());

        String rotatedJson = mockMvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(refreshJson(second.refreshToken())))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String rotatedAccess = JsonPath.read(rotatedJson, "$.accessToken");
        String rotatedRefresh = JsonPath.read(rotatedJson, "$.refreshToken");
        assertThat(rotatedRefresh).isNotEqualTo(second.refreshToken());

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(refreshJson(second.refreshToken())))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/api/v1/auth/logout")
                        .header(HttpHeaders.AUTHORIZATION, bearer(rotatedAccess)))
                .andExpect(status().isNoContent());

        mockMvc.perform(get("/api/v1/users/me")
                        .header(HttpHeaders.AUTHORIZATION, bearer(rotatedAccess)))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(refreshJson(rotatedRefresh)))
                .andExpect(status().isUnauthorized());
    }

    private static OidcUser identity(String subject, String email) {
        Instant now = Instant.now();
        OidcIdToken token = new OidcIdToken(
                "test-id-token",
                now,
                now.plusSeconds(300),
                Map.of(
                        "iss", "https://accounts.google.com",
                        "aud", List.of(CLIENT_ID),
                        "sub", subject,
                        "email", email,
                        "email_verified", true,
                        "name", "Google Integration User"
                )
        );
        OidcUser user = mock(OidcUser.class);
        when(user.getIdToken()).thenReturn(token);
        return user;
    }

    private static String bearer(String token) {
        return "Bearer " + token;
    }

    private static String refreshJson(String token) {
        return "{\"refreshToken\":\"" + token + "\"}";
    }
}
