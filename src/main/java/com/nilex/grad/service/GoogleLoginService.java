package com.nilex.grad.service;

import com.nilex.grad.dto.AuthenticatedUserResponse;
import com.nilex.grad.dto.LoginResponse;
import com.nilex.grad.dto.SessionCredentials;
import com.nilex.grad.exception.GoogleAccountConflictException;
import com.nilex.grad.exception.InvalidCredentialsException;
import com.nilex.grad.model.User;
import com.nilex.grad.repository.UserRepository;
import com.nilex.grad.security.IssuedAccessToken;
import com.nilex.grad.security.JwtAccessTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.util.List;
import java.util.Locale;

@Service
@RequiredArgsConstructor
public class GoogleLoginService {

    private static final List<String> GOOGLE_ISSUERS =
            List.of("https://accounts.google.com", "accounts.google.com");

    private final UserRepository userRepository;
    private final SessionService sessionService;
    private final JwtAccessTokenService accessTokenService;
    private final Clock clock;

    @Transactional
    public LoginResponse login(OidcUser identity, String expectedClientId) {
        OidcIdToken idToken = identity.getIdToken();
        if (idToken == null
                || !GOOGLE_ISSUERS.contains(idToken.getClaimAsString("iss"))
                || !idToken.getAudience().contains(expectedClientId)
                || idToken.getExpiresAt() == null
                || !idToken.getExpiresAt().isAfter(clock.instant())
                || !Boolean.TRUE.equals(idToken.getClaim("email_verified"))) {
            throw new InvalidCredentialsException();
        }

        String subject = idToken.getSubject();
        String rawEmail = idToken.getClaimAsString("email");
        if (subject == null || subject.isBlank() || subject.length() > 255
                || rawEmail == null || rawEmail.isBlank() || rawEmail.length() > 320) {
            throw new InvalidCredentialsException();
        }

        String email = rawEmail.trim().toLowerCase(Locale.ROOT);
        if (!email.contains("@")) {
            throw new InvalidCredentialsException();
        }

        User user = userRepository.findByGoogleSubject(subject)
                .orElseGet(() -> createGoogleUser(idToken, email, subject));
        if (!user.isActive() || !user.getEmail().equalsIgnoreCase(email)) {
            throw new InvalidCredentialsException();
        }

        SessionCredentials session = sessionService.start(user);
        IssuedAccessToken token = accessTokenService.issueFor(user, session.sessionId());
        return new LoginResponse(
                token.value(),
                "Bearer",
                token.expiresInSeconds(),
                token.expiresAt(),
                session.refreshToken(),
                session.refreshExpiresInSeconds(),
                session.refreshExpiresAt(),
                AuthenticatedUserResponse.from(user)
        );
    }

    private User createGoogleUser(OidcIdToken idToken, String email, String subject) {
        if (userRepository.existsByEmailIgnoreCase(email)) {
            throw new GoogleAccountConflictException();
        }

        String name = idToken.getClaimAsString("name");
        if (name == null || name.isBlank()) {
            name = email;
        }
        name = name.trim();
        if (name.length() > 120) {
            name = name.substring(0, 120);
        }

        try {
            return userRepository.saveAndFlush(User.googleRegistered(name, email, subject));
        } catch (DataIntegrityViolationException exception) {
            throw new GoogleAccountConflictException();
        }
    }
}
