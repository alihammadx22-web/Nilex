package com.nilex.grad.dto;

import com.nilex.grad.model.User;
import com.nilex.grad.model.UserRole;

import java.time.Instant;
import java.util.UUID;

public record RegisterResponse(
        UUID id,
        String name,
        String email,
        UserRole role,
        boolean active,
        Instant createdAt
) {
    public static RegisterResponse from(User user) {
        return new RegisterResponse(
                user.getId(),
                user.getName(),
                user.getEmail(),
                user.getRole(),
                user.isActive(),
                user.getCreatedAt()
        );
    }
}
