package com.nilex.grad.controller;

import com.jayway.jsonpath.JsonPath;
import com.nilex.grad.model.User;
import com.nilex.grad.repository.UserRepository;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.Rollback;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
@Rollback
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@Import(CompleteAuthenticationFlowIntegrationTest.RoleEndpointConfiguration.class)
class CompleteAuthenticationFlowIntegrationTest {

    private static final String PASSWORD = "complete-flow-password";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private EntityManager entityManager;

    @Test
    void completeUserFlowSupportsProfileRefreshLogoutAndRevocation() throws Exception {
        String email = "phase4-flow-" + UUID.randomUUID() + "@example.invalid";

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "name":"Complete Flow User",
                                  "email":"%s",
                                  "password":"%s"
                                }
                                """.formatted(email, PASSWORD)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.passwordHash").doesNotExist());

        TokenPair loginTokens = login(email.toUpperCase(), PASSWORD);
        mockMvc.perform(get("/api/v1/users/me")
                        .header(HttpHeaders.AUTHORIZATION, bearer(loginTokens.accessToken())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.name").value("Complete Flow User"))
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.role").value("USER"))
                .andExpect(jsonPath("$.active").value(true))
                .andExpect(jsonPath("$.createdAt").exists())
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.passwordHash").doesNotExist());

        mockMvc.perform(get("/api/v1/test/admin")
                        .header(HttpHeaders.AUTHORIZATION, bearer(loginTokens.accessToken())))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("FORBIDDEN"));

        TokenPair refreshed = refresh(loginTokens.refreshToken());
        assertThat(refreshed.refreshToken()).isNotEqualTo(loginTokens.refreshToken());

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(refreshJson(loginTokens.refreshToken())))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHORIZED"));

        mockMvc.perform(get("/api/v1/users/me")
                        .header(HttpHeaders.AUTHORIZATION, bearer(refreshed.accessToken())))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/v1/auth/logout")
                        .header(HttpHeaders.AUTHORIZATION, bearer(refreshed.accessToken())))
                .andExpect(status().isNoContent());

        mockMvc.perform(get("/api/v1/users/me")
                        .header(HttpHeaders.AUTHORIZATION, bearer(refreshed.accessToken())))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHORIZED"));

        mockMvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(refreshJson(refreshed.refreshToken())))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void adminRoleIsMappedAndAuthorizedWithoutTrustingClientInput() throws Exception {
        User user = userRepository.saveAndFlush(User.registered(
                "NILEX Administrator",
                "phase4-admin-" + UUID.randomUUID() + "@example.invalid",
                passwordEncoder.encode(PASSWORD)
        ));
        jdbcTemplate.update("UPDATE app_users SET role = 'ADMIN' WHERE id = ?", user.getId());
        entityManager.clear();

        TokenPair tokens = login(user.getEmail(), PASSWORD);
        mockMvc.perform(get("/api/v1/test/admin")
                        .header(HttpHeaders.AUTHORIZATION, bearer(tokens.accessToken())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.role").value("ADMIN"));

        mockMvc.perform(get("/api/v1/users/me")
                        .header(HttpHeaders.AUTHORIZATION, bearer(tokens.accessToken())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.role").value("ADMIN"));
    }

    @Test
    void openApiDocumentsAllAuthenticationEndpointsAndBearerSecurity() throws Exception {
        mockMvc.perform(get("/v3/api-docs"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.info.title").value("NILEX API"))
                .andExpect(jsonPath("$.paths['/api/v1/auth/register'].post").exists())
                .andExpect(jsonPath("$.paths['/api/v1/auth/login'].post").exists())
                .andExpect(jsonPath("$.paths['/api/v1/auth/refresh'].post").exists())
                .andExpect(jsonPath("$.paths['/api/v1/auth/logout'].post").exists())
                .andExpect(jsonPath("$.paths['/api/v1/users/me'].get").exists())
                .andExpect(jsonPath("$.components.securitySchemes.bearerAuth.type").value("http"))
                .andExpect(jsonPath("$.components.securitySchemes.bearerAuth.scheme").value("bearer"))
                .andExpect(jsonPath("$.components.securitySchemes.bearerAuth.bearerFormat").value("JWT"))
                .andExpect(jsonPath("$.paths['/api/v1/auth/logout'].post.security[0].bearerAuth").exists())
                .andExpect(jsonPath("$.paths['/api/v1/users/me'].get.security[0].bearerAuth").exists())
                .andExpect(content().string(not(containsString("passwordHash"))))
                .andExpect(content().string(not(containsString("refreshTokenHash"))));

        int swaggerStatus = mockMvc.perform(get("/swagger-ui.html"))
                .andReturn().getResponse().getStatus();
        assertThat(swaggerStatus).isIn(200, 302);
    }

    private TokenPair login(String email, String password) throws Exception {
        String response = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"%s","password":"%s"}
                                """.formatted(email, password)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.expiresIn").value(1_800))
                .andExpect(jsonPath("$.refreshExpiresIn").value(2_592_000))
                .andReturn().getResponse().getContentAsString();
        return tokenPair(response);
    }

    private TokenPair refresh(String refreshToken) throws Exception {
        String response = mockMvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(refreshJson(refreshToken)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return tokenPair(response);
    }

    private static TokenPair tokenPair(String response) {
        return new TokenPair(
                JsonPath.read(response, "$.accessToken"),
                JsonPath.read(response, "$.refreshToken")
        );
    }

    private static String refreshJson(String refreshToken) {
        return """
                {"refreshToken":"%s"}
                """.formatted(refreshToken);
    }

    private static String bearer(String accessToken) {
        return "Bearer " + accessToken;
    }

    private record TokenPair(String accessToken, String refreshToken) {
        @Override
        public String toString() {
            return "TokenPair[accessToken=[REDACTED], refreshToken=[REDACTED]]";
        }
    }

    @TestConfiguration
    static class RoleEndpointConfiguration {

        @RestController
        static class RoleEndpoint {

            @GetMapping("/api/v1/test/admin")
            @PreAuthorize("hasRole('ADMIN')")
            RoleResponse adminOnly() {
                return new RoleResponse("ADMIN");
            }
        }

        record RoleResponse(String role) {
        }
    }
}
