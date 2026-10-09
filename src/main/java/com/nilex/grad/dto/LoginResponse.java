package com.nilex.grad.dto;

import java.time.Instant;

public record LoginResponse(
        String accessToken,
        String tokenType,
        long expiresIn,
        Instant expiresAt,
        String refreshToken,
        long refreshExpiresIn,
        Instant refreshExpiresAt,
        AuthenticatedUserResponse user
) {
    @Override
    public String toString() {
        return "LoginResponse[accessToken=[REDACTED], tokenType=%s, expiresIn=%d, expiresAt=%s, "
                + "refreshToken=[REDACTED], refreshExpiresIn=%d, refreshExpiresAt=%s, user=%s]"
                .formatted(
                        tokenType,
                        expiresIn,
                        expiresAt,
                        refreshExpiresIn,
                        refreshExpiresAt,
                        user
                );
    }
}
