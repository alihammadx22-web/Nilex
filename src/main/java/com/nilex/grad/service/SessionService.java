package com.nilex.grad.service;

import com.nilex.grad.dto.SessionCredentials;
import com.nilex.grad.model.AuthSession;
import com.nilex.grad.repository.AuthSessionRepository;
import com.nilex.grad.security.RefreshTokenCodec;

import com.nilex.grad.exception.InvalidCredentialsException;
import com.nilex.grad.model.User;
import com.nilex.grad.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class SessionService {

    public static final Duration REFRESH_TOKEN_TTL = Duration.ofDays(30);

    private final AuthSessionRepository sessionRepository;
    private final UserRepository userRepository;
    private final RefreshTokenCodec refreshTokenCodec;
    private final Clock clock;

    @Transactional
    public SessionCredentials start(User authenticatedUser) {
        User lockedUser = userRepository.findByIdForUpdate(authenticatedUser.getId())
                .orElseThrow(InvalidCredentialsException::new);
        if (!lockedUser.isActive()) {
            throw new InvalidCredentialsException();
        }

        Instant now = clock.instant();
        sessionRepository.findActiveByUserIdForUpdate(lockedUser.getId())
                .forEach(session -> session.revoke(now));
        sessionRepository.flush();

        String refreshToken = refreshTokenCodec.generate();
        Instant expiresAt = now.plus(REFRESH_TOKEN_TTL);
        AuthSession session = AuthSession.start(
                lockedUser,
                refreshTokenCodec.hash(refreshToken),
                expiresAt
        );
        sessionRepository.saveAndFlush(session);

        return credentials(session, refreshToken, expiresAt);
    }

    @Transactional
    public SessionCredentials rotate(String presentedRefreshToken) {
        String tokenHash = refreshTokenCodec.hash(presentedRefreshToken);
        AuthSession session = sessionRepository.findByRefreshTokenHashForUpdate(tokenHash)
                .orElseThrow(InvalidCredentialsException::new);
        Instant now = clock.instant();
        if (!session.isUsableAt(now)) {
            throw new InvalidCredentialsException();
        }

        String newRefreshToken = refreshTokenCodec.generate();
        Instant newExpiresAt = now.plus(REFRESH_TOKEN_TTL);
        session.rotate(refreshTokenCodec.hash(newRefreshToken), newExpiresAt, now);
        sessionRepository.saveAndFlush(session);

        return credentials(session, newRefreshToken, newExpiresAt);
    }

    @Transactional
    public void revoke(UUID sessionId) {
        AuthSession session = sessionRepository.findByIdForUpdate(sessionId)
                .orElseThrow(InvalidCredentialsException::new);
        session.revoke(clock.instant());
        sessionRepository.saveAndFlush(session);
    }

    private static SessionCredentials credentials(
            AuthSession session,
            String refreshToken,
            Instant expiresAt
    ) {
        return new SessionCredentials(
                session.getId(),
                session.getUser(),
                refreshToken,
                REFRESH_TOKEN_TTL.toSeconds(),
                expiresAt
        );
    }
}
