package com.nilex.grad.security;

import java.time.Instant;

public record IssuedAccessToken(
        String value,
        long expiresInSeconds,
        Instant expiresAt
) {
    @Override
    public String toString() {
        return "IssuedAccessToken[value=[REDACTED], expiresInSeconds=%d, expiresAt=%s]"
                .formatted(expiresInSeconds, expiresAt);
    }
}
