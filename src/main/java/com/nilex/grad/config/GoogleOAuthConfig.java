package com.nilex.grad.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;

@Configuration
@ConditionalOnProperty(prefix = "google.oauth", name = {"client-id", "client-secret"})
public class GoogleOAuthConfig {

    public static final String CALLBACK_URI = "http://localhost:8080/login/oauth2/code/google";

    @Bean
    ClientRegistrationRepository googleClientRegistrationRepository(
            @Value("${google.oauth.client-id}") String clientId,
            @Value("${google.oauth.client-secret}") String clientSecret
    ) {
        if (clientId.isBlank() || clientSecret.isBlank()) {
            throw new IllegalStateException("Google OAuth client ID and secret must not be blank");
        }
        return new InMemoryClientRegistrationRepository(
                CommonOAuth2Provider.GOOGLE.getBuilder("google")
                        .clientId(clientId)
                        .clientSecret(clientSecret)
                        .scope("openid", "profile", "email")
                        .redirectUri(CALLBACK_URI)
                        .build()
        );
    }
}
