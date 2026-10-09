package com.nilex.grad.dto;

import com.nilex.grad.model.User;

import java.time.Instant;
import java.util.UUID;

public record SessionCredentials(
        UUID sessionId,
        User user,
        String refreshToken,
        long refreshExpiresInSeconds,
        Instant refreshExpiresAt
) {
    @Override
    public String toString() {
        return "SessionCredentials[sessionId=%s, userId=%s, refreshToken=[REDACTED], "
                + "refreshExpiresInSeconds=%d, refreshExpiresAt=%s]"
                .formatted(sessionId, user.getId(), refreshExpiresInSeconds, refreshExpiresAt);
    }
}
