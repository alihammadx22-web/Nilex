package com.nilex.grad.repository;

import com.nilex.grad.model.AuthSession;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface AuthSessionRepository extends JpaRepository<AuthSession, UUID> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select s from AuthSession s join fetch s.user where s.refreshTokenHash = :tokenHash")
    Optional<AuthSession> findByRefreshTokenHashForUpdate(@Param("tokenHash") String tokenHash);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select s from AuthSession s join fetch s.user where s.id = :sessionId")
    Optional<AuthSession> findByIdForUpdate(@Param("sessionId") UUID sessionId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            select s
              from AuthSession s
             where s.user.id = :userId
               and s.revokedAt is null
            """)
    List<AuthSession> findActiveByUserIdForUpdate(@Param("userId") UUID userId);

    @Query("""
            select (count(s) > 0)
              from AuthSession s
             where s.id = :sessionId
               and s.user.id = :userId
               and s.user.active = true
               and s.revokedAt is null
               and s.expiresAt > :now
            """)
    boolean isActiveSession(
            @Param("sessionId") UUID sessionId,
            @Param("userId") UUID userId,
            @Param("now") Instant now
    );

    long countByUser_IdAndRevokedAtIsNull(UUID userId);
}
