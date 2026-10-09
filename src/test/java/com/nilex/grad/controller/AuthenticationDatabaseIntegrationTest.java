package com.nilex.grad.controller;

import com.jayway.jsonpath.JsonPath;
import com.nilex.grad.config.JwtProperties;
import com.nilex.grad.model.AuthSession;
import com.nilex.grad.repository.AuthSessionRepository;
import com.nilex.grad.security.RefreshTokenCodec;
import com.nilex.grad.model.User;
import com.nilex.grad.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.test.annotation.Rollback;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
@Rollback
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@Import(AuthenticationDatabaseIntegrationTest.ProtectedEndpointConfiguration.class)
class AuthenticationDatabaseIntegrationTest {

    private static final String PASSWORD = "database-test-password";
    private static final String UNAUTHORIZED_MESSAGE =
            "Authentication is required or the supplied credentials are invalid";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtEncoder jwtEncoder;

    @Autowired
    private JwtProperties jwtProperties;

    @Autowired
    private AuthSessionRepository sessionRepository;

    @Autowired
    private RefreshTokenCodec refreshTokenCodec;

    @Test
    void caseInsensitiveLoginIssuesTokenThatAuthenticatesAProtectedEndpoint() throws Exception {
        User user = createUser();

        String response = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson(user.getEmail().toUpperCase(), PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(1_800))
                .andExpect(jsonPath("$.refreshExpiresIn").value(2_592_000))
                .andExpect(jsonPath("$.user.role").value("USER"))
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.user.passwordHash").doesNotExist())
                .andReturn().getResponse().getContentAsString();

        String accessToken = JsonPath.read(response, "$.accessToken");
        mockMvc.perform(get("/api/v1/test/protected")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.subject").value(user.getId().toString()))
                .andExpect(jsonPath("$.authority").value("ROLE_USER"));
    }

    @Test
    void storesOnlyRefreshTokenHashAndRotatesOnEveryUse() throws Exception {
        User user = createUser();
        TokenPair first = login(user, user.getEmail());

        AuthSession stored = sessionRepository.findByRefreshTokenHashForUpdate(
                refreshTokenCodec.hash(first.refreshToken())
        ).orElseThrow();
        assertThat(stored.getRefreshTokenHash()).hasSize(64);
        assertThat(stored.getRefreshTokenHash()).isNotEqualTo(first.refreshToken());
        assertThat(stored.getExpiresAt()).isAfter(Instant.now().plus(Duration.ofDays(29)));

        TokenPair rotated = refresh(first.refreshToken());
        assertThat(rotated.refreshToken()).isNotEqualTo(first.refreshToken());
        assertThat(rotated.accessToken()).isNotEqualTo(first.accessToken());

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(refreshJson(first.refreshToken())))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHORIZED"));

        mockMvc.perform(get("/api/v1/test/protected")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + rotated.accessToken()))
                .andExpect(status().isOk());
    }

    @Test
    void expiredRefreshTokenIsRejected() throws Exception {
        User user = createUser();
        String expiredToken = "expired-" + UUID.randomUUID();
        sessionRepository.saveAndFlush(AuthSession.start(
                user,
                refreshTokenCodec.hash(expiredToken),
                Instant.now().minusSeconds(1)
        ));

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(refreshJson(expiredToken)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value(UNAUTHORIZED_MESSAGE));
    }

    @Test
    void logoutRevokesBothAccessAndRefreshTokensImmediately() throws Exception {
        User user = createUser();
        TokenPair tokens = login(user, user.getEmail());

        mockMvc.perform(post("/api/v1/auth/logout")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + tokens.accessToken()))
                .andExpect(status().isNoContent());

        assertUnauthorizedToken(tokens.accessToken());
        mockMvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(refreshJson(tokens.refreshToken())))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
    }

    @Test
    void secondLoginRevokesTheFirstDeviceSession() throws Exception {
        User user = createUser();
        TokenPair firstDevice = login(user, user.getEmail());
        TokenPair secondDevice = login(user, user.getEmail().toUpperCase());

        assertThat(sessionRepository.countByUser_IdAndRevokedAtIsNull(user.getId())).isEqualTo(1);
        assertUnauthorizedToken(firstDevice.accessToken());
        mockMvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(refreshJson(firstDevice.refreshToken())))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(get("/api/v1/test/protected")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + secondDevice.accessToken()))
                .andExpect(status().isOk());
    }

    @Test
    void wrongPasswordReturnsStandardUnauthorizedResponse() throws Exception {
        User user = createUser();

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson(user.getEmail(), "incorrect-password")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHORIZED"))
                .andExpect(jsonPath("$.message").value(UNAUTHORIZED_MESSAGE));
    }

    @Test
    void expiredTokenReturnsStandardUnauthorizedResponse() throws Exception {
        User user = createUser();
        Instant issuedAt = Instant.now().minus(Duration.ofHours(2));
        String expiredToken = encodeToken(user, issuedAt, issuedAt.plus(Duration.ofMinutes(30)));

        assertUnauthorizedToken(expiredToken);
    }

    @Test
    void invalidSignatureReturnsStandardUnauthorizedResponse() throws Exception {
        User user = createUser();
        Instant issuedAt = Instant.now();
        String validToken = encodeToken(user, issuedAt, issuedAt.plus(Duration.ofMinutes(30)));
        String[] segments = validToken.split("\\.");
        char replacement = segments[2].charAt(0) == 'A' ? 'B' : 'A';
        segments[2] = replacement + segments[2].substring(1);

        assertUnauthorizedToken(String.join(".", segments));
    }

    private void assertUnauthorizedToken(String token) throws Exception {
        mockMvc.perform(get("/api/v1/test/protected")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHORIZED"))
                .andExpect(jsonPath("$.message").value(UNAUTHORIZED_MESSAGE));
    }

    private TokenPair login(User user, String email) throws Exception {
        String response = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson(email, PASSWORD)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return new TokenPair(
                JsonPath.read(response, "$.accessToken"),
                JsonPath.read(response, "$.refreshToken")
        );
    }

    private TokenPair refresh(String refreshToken) throws Exception {
        String response = mockMvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(refreshJson(refreshToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.expiresIn").value(1_800))
                .andExpect(jsonPath("$.refreshExpiresIn").value(2_592_000))
                .andReturn().getResponse().getContentAsString();
        return new TokenPair(
                JsonPath.read(response, "$.accessToken"),
                JsonPath.read(response, "$.refreshToken")
        );
    }

    private User createUser() {
        String email = "phase2-" + UUID.randomUUID() + "@example.invalid";
        return userRepository.saveAndFlush(User.registered(
                "Authentication Verification User",
                email,
                passwordEncoder.encode(PASSWORD)
        ));
    }

    private String encodeToken(User user, Instant issuedAt, Instant expiresAt) {
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(jwtProperties.issuer())
                .subject(user.getId().toString())
                .audience(List.of(jwtProperties.audience()))
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .claim("roles", List.of(user.getRole().name()))
                .build();
        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).type("JWT").build();
        return jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }

    private static String loginJson(String email, String password) {
        return """
                {
                  "email": "%s",
                  "password": "%s"
                }
                """.formatted(email, password);
    }

    private static String refreshJson(String refreshToken) {
        return """
                {"refreshToken":"%s"}
                """.formatted(refreshToken);
    }

    private record TokenPair(String accessToken, String refreshToken) {
        @Override
        public String toString() {
            return "TokenPair[accessToken=[REDACTED], refreshToken=[REDACTED]]";
        }
    }

    @TestConfiguration
    static class ProtectedEndpointConfiguration {

        @RestController
        static class ProtectedEndpoint {

            @GetMapping("/api/v1/test/protected")
            Map<String, String> protectedEndpoint(Authentication authentication) {
                String authority = authentication.getAuthorities().stream()
                        .map(grantedAuthority -> grantedAuthority.getAuthority())
                        .filter(value -> value.startsWith("ROLE_"))
                        .findFirst()
                        .orElseThrow();
                return Map.of("subject", authentication.getName(), "authority", authority);
            }
        }
    }
}
