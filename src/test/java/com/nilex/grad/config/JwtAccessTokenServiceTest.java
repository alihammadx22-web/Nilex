package com.nilex.grad.config;

import com.nilex.grad.model.User;
import com.nilex.grad.model.UserRole;
import com.nilex.grad.repository.AuthSessionRepository;
import com.nilex.grad.security.IssuedAccessToken;
import com.nilex.grad.security.JwtAccessTokenService;
import com.nilex.grad.security.SessionTokenValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtEncoder;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwtAccessTokenServiceTest {

    private static final String ISSUER = "nilex-api";
    private static final String AUDIENCE = "nilex-client";
    private static final Duration TTL = Duration.ofMinutes(30);

    private JwtConfig jwtConfig;
    private JwtProperties properties;
    private SecretKey secretKey;
    private JwtEncoder encoder;
    private JwtDecoder decoder;
    private SessionTokenValidator sessionTokenValidator;
    private User user;

    @BeforeEach
    void setUp() {
        jwtConfig = new JwtConfig();
        properties = propertiesFor("01234567890123456789012345678901", ISSUER, AUDIENCE);
        secretKey = jwtConfig.jwtSecretKey(properties);
        encoder = jwtConfig.jwtEncoder(secretKey);
        AuthSessionRepository sessionRepository = mock(AuthSessionRepository.class);
        when(sessionRepository.isActiveSession(
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any()
        )).thenReturn(true);
        sessionTokenValidator = new SessionTokenValidator(sessionRepository, Clock.systemUTC());
        decoder = jwtConfig.jwtDecoder(secretKey, properties, sessionTokenValidator);

        user = mock(User.class);
        when(user.getId()).thenReturn(UUID.randomUUID());
        when(user.getEmail()).thenReturn("person@example.com");
        when(user.getRole()).thenReturn(UserRole.USER);
    }

    @Test
    void issuesHs256TokenWithThirtyMinuteLifetimeAndRequiredClaims() {
        Instant issuedAt = Instant.now();
        JwtAccessTokenService service = service(properties, encoder, issuedAt);
        UUID sessionId = UUID.randomUUID();

        IssuedAccessToken token = service.issueFor(user, sessionId);
        Jwt decoded = decoder.decode(token.value());

        assertThat(decoded.getHeaders().get("alg")).isEqualTo("HS256");
        assertThat(decoded.getClaimAsString("iss")).isEqualTo(ISSUER);
        assertThat(decoded.getAudience()).containsExactly(AUDIENCE);
        assertThat(decoded.getSubject()).isEqualTo(user.getId().toString());
        assertThat(decoded.getClaimAsStringList("roles")).containsExactly("USER");
        assertThat(decoded.getClaimAsString("sid")).isEqualTo(sessionId.toString());
        assertThat(Duration.between(decoded.getIssuedAt(), decoded.getExpiresAt())).isEqualTo(TTL);
        assertThat(token.expiresInSeconds()).isEqualTo(1_800);
    }

    @Test
    void rejectsExpiredToken() {
        Instant twoHoursAgo = Instant.now().minus(Duration.ofHours(2));
        String token = service(properties, encoder, twoHoursAgo)
                .issueFor(user, UUID.randomUUID()).value();

        assertThatThrownBy(() -> decoder.decode(token)).isInstanceOf(JwtException.class);
    }

    @Test
    void rejectsTokenSignedWithAnotherSecret() {
        JwtProperties other = propertiesFor("abcdefghijklmnopqrstuvwxyzABCDEF", ISSUER, AUDIENCE);
        SecretKey otherKey = jwtConfig.jwtSecretKey(other);
        JwtEncoder otherEncoder = jwtConfig.jwtEncoder(otherKey);
        String token = service(other, otherEncoder, Instant.now())
                .issueFor(user, UUID.randomUUID()).value();

        assertThatThrownBy(() -> decoder.decode(token)).isInstanceOf(JwtException.class);
    }

    @Test
    void rejectsWrongIssuerAndWrongAudience() {
        JwtProperties wrongIssuer = propertiesFor(
                "01234567890123456789012345678901",
                "another-issuer",
                AUDIENCE
        );
        String wrongIssuerToken = service(wrongIssuer, encoder, Instant.now())
                .issueFor(user, UUID.randomUUID()).value();

        JwtProperties wrongAudience = propertiesFor(
                "01234567890123456789012345678901",
                ISSUER,
                "another-audience"
        );
        String wrongAudienceToken = service(wrongAudience, encoder, Instant.now())
                .issueFor(user, UUID.randomUUID()).value();

        assertThatThrownBy(() -> decoder.decode(wrongIssuerToken)).isInstanceOf(JwtException.class);
        assertThatThrownBy(() -> decoder.decode(wrongAudienceToken)).isInstanceOf(JwtException.class);
    }

    private JwtAccessTokenService service(JwtProperties tokenProperties, JwtEncoder tokenEncoder, Instant now) {
        return new JwtAccessTokenService(
                tokenEncoder,
                tokenProperties,
                Clock.fixed(now, ZoneOffset.UTC)
        );
    }

    private static JwtProperties propertiesFor(String keyMaterial, String issuer, String audience) {
        String base64Secret = Base64.getEncoder().encodeToString(
                keyMaterial.getBytes(StandardCharsets.UTF_8)
        );
        return new JwtProperties(base64Secret, issuer, audience, TTL);
    }
}
