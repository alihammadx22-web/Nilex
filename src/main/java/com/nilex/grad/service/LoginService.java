package com.nilex.grad.service;

import com.nilex.grad.dto.AuthenticatedUserResponse;
import com.nilex.grad.dto.LoginRequest;
import com.nilex.grad.dto.LoginResponse;
import com.nilex.grad.exception.InvalidCredentialsException;

import com.nilex.grad.security.JwtAccessTokenService;
import com.nilex.grad.security.IssuedAccessToken;
import com.nilex.grad.dto.SessionCredentials;
import com.nilex.grad.model.User;
import com.nilex.grad.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Locale;
import java.util.Optional;

@Service
public class LoginService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtAccessTokenService accessTokenService;
    private final SessionService sessionService;
    private final String dummyPasswordHash;

    public LoginService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtAccessTokenService accessTokenService,
            SessionService sessionService
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.accessTokenService = accessTokenService;
        this.sessionService = sessionService;
        this.dummyPasswordHash = passwordEncoder.encode("nilex-dummy-password");
    }

    @Transactional
    public LoginResponse login(LoginRequest request) {
        String email = request.email().trim().toLowerCase(Locale.ROOT);
        Optional<User> possibleUser = userRepository.findByEmailIgnoreCase(email);
        String passwordHash = possibleUser.map(User::getPasswordHash)
                .filter(hash -> !hash.isBlank())
                .orElse(dummyPasswordHash);
        boolean passwordMatches = passwordEncoder.matches(request.password(), passwordHash);

        if (possibleUser.isEmpty() || !passwordMatches
                || possibleUser.get().getPasswordHash() == null
                || !possibleUser.get().isActive()) {
            throw new InvalidCredentialsException();
        }

        User user = possibleUser.get();
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
}
