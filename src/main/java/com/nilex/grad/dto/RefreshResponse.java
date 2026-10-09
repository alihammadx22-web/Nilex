package com.nilex.grad.dto;

import java.time.Instant;

public record RefreshResponse(
        String accessToken,
        String tokenType,
        long expiresIn,
        Instant expiresAt,
        String refreshToken,
        long refreshExpiresIn,
        Instant refreshExpiresAt
) {
    @Override
    public String toString() {
        return "RefreshResponse[accessToken=[REDACTED], tokenType=%s, expiresIn=%d, expiresAt=%s, "
                + "refreshToken=[REDACTED], refreshExpiresIn=%d, refreshExpiresAt=%s]"
                .formatted(
                        tokenType,
                        expiresIn,
                        expiresAt,
                        refreshExpiresIn,
                        refreshExpiresAt
                );
    }
}
