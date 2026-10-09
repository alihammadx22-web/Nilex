package com.nilex.grad.service;

import com.nilex.grad.dto.RefreshRequest;
import com.nilex.grad.dto.RefreshResponse;

import com.nilex.grad.security.JwtAccessTokenService;
import com.nilex.grad.security.IssuedAccessToken;
import com.nilex.grad.dto.SessionCredentials;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class RefreshService {

    private final SessionService sessionService;
    private final JwtAccessTokenService accessTokenService;

    @Transactional
    public RefreshResponse refresh(RefreshRequest request) {
        SessionCredentials session = sessionService.rotate(request.refreshToken());
        IssuedAccessToken accessToken = accessTokenService.issueFor(
                session.user(),
                session.sessionId()
        );
        return new RefreshResponse(
                accessToken.value(),
                "Bearer",
                accessToken.expiresInSeconds(),
                accessToken.expiresAt(),
                session.refreshToken(),
                session.refreshExpiresInSeconds(),
                session.refreshExpiresAt()
        );
    }
}
