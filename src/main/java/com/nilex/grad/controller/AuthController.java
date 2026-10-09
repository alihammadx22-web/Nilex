package com.nilex.grad.controller;

import com.nilex.grad.dto.LoginRequest;
import com.nilex.grad.dto.LoginResponse;
import com.nilex.grad.dto.RefreshRequest;
import com.nilex.grad.dto.RefreshResponse;
import com.nilex.grad.dto.RegisterRequest;
import com.nilex.grad.dto.RegisterResponse;
import com.nilex.grad.service.LoginService;
import com.nilex.grad.service.RefreshService;
import com.nilex.grad.service.RegistrationService;
import com.nilex.grad.config.OpenApiConfig;
import com.nilex.grad.service.SessionService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth")
@Tag(name = "Authentication", description = "Registration, login, token refresh, and logout")
@RequiredArgsConstructor
public class AuthController {

    private final RegistrationService registrationService;
    private final LoginService loginService;
    private final RefreshService refreshService;
    private final SessionService sessionService;

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Register a user account")
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "User registered"),
            @ApiResponse(responseCode = "400", description = "Validation failed"),
            @ApiResponse(responseCode = "409", description = "Email already registered")
    })
    public RegisterResponse register(@Valid @RequestBody RegisterRequest request) {
        return registrationService.register(request);
    }

    @PostMapping("/login")
    @Operation(summary = "Log in and create a single-device session")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Access and refresh tokens issued"),
            @ApiResponse(responseCode = "400", description = "Malformed request"),
            @ApiResponse(responseCode = "401", description = "Invalid credentials")
    })
    public LoginResponse login(@Valid @RequestBody LoginRequest request) {
        return loginService.login(request);
    }

    @PostMapping("/refresh")
    @Operation(summary = "Rotate a refresh token and issue a new token pair")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Token pair rotated"),
            @ApiResponse(responseCode = "400", description = "Malformed request"),
            @ApiResponse(responseCode = "401", description = "Expired, reused, or revoked refresh token")
    })
    public RefreshResponse refresh(@Valid @RequestBody RefreshRequest request) {
        return refreshService.refresh(request);
    }

    @PostMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(
            summary = "Revoke the current session",
            security = @SecurityRequirement(name = OpenApiConfig.BEARER_AUTH)
    )
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "Session revoked"),
            @ApiResponse(responseCode = "401", description = "Invalid token or inactive session")
    })
    public void logout(@AuthenticationPrincipal Jwt jwt) {
        sessionService.revoke(UUID.fromString(jwt.getClaimAsString("sid")));
    }
}
