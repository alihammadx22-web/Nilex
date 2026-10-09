package com.nilex.grad.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "security.jwt")
public record JwtProperties(
        String secret,
        String issuer,
        String audience,
        Duration accessTokenTtl
) {
    @Override
    public String toString() {
        return "JwtProperties[secret=[REDACTED], issuer=%s, audience=%s, accessTokenTtl=%s]"
                .formatted(issuer, audience, accessTokenTtl);
    }
}
