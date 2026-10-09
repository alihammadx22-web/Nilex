package com.nilex.grad.controller;

import com.jayway.jsonpath.JsonPath;
import com.nilex.grad.repository.AuthSessionRepository;
import com.nilex.grad.model.User;
import com.nilex.grad.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

@SpringBootTest
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@Import(AuthenticationDatabaseIntegrationTest.ProtectedEndpointConfiguration.class)
class SessionConcurrencyIntegrationTest {

    private static final String PASSWORD = "concurrency-test-password";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuthSessionRepository sessionRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    void simultaneousLoginsLeaveExactlyOneUsableDeviceSession() throws Exception {
        User user = createCommittedUser();
        try {
            List<HttpTokenResponse> responses = runTogether(
                    () -> login(user.getEmail()),
                    () -> login(user.getEmail().toUpperCase())
            );

            assertThat(responses).extracting(HttpTokenResponse::status).containsExactlyInAnyOrder(200, 200);
            assertThat(sessionRepository.countByUser_IdAndRevokedAtIsNull(user.getId())).isEqualTo(1);

            List<Integer> accessStatuses = responses.stream()
                    .map(response -> tokenPair(response.body()).accessToken())
                    .map(this::protectedStatus)
                    .toList();
            assertThat(accessStatuses).containsExactlyInAnyOrder(200, 401);
        } finally {
            userRepository.deleteById(user.getId());
        }
    }

    @Test
    void simultaneousRefreshesAllowExactlyOneRotation() throws Exception {
        User user = createCommittedUser();
        try {
            TokenPair initial = tokenPair(login(user.getEmail()).body());
            List<HttpTokenResponse> responses = runTogether(
                    () -> refresh(initial.refreshToken()),
                    () -> refresh(initial.refreshToken())
            );

            assertThat(responses).extracting(HttpTokenResponse::status).containsExactlyInAnyOrder(200, 401);
            HttpTokenResponse successful = responses.stream()
                    .filter(response -> response.status() == 200)
                    .findFirst()
                    .orElseThrow();
            assertThat(protectedStatus(tokenPair(successful.body()).accessToken())).isEqualTo(200);
            assertThat(refresh(initial.refreshToken()).status()).isEqualTo(401);
        } finally {
            userRepository.deleteById(user.getId());
        }
    }

    private User createCommittedUser() {
        return userRepository.saveAndFlush(User.registered(
                "Concurrency Verification User",
                "phase3-concurrency-" + UUID.randomUUID() + "@example.invalid",
                passwordEncoder.encode(PASSWORD)
        ));
    }

    private HttpTokenResponse login(String email) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"%s","password":"%s"}
                                """.formatted(email, PASSWORD)))
                .andReturn();
        return new HttpTokenResponse(
                result.getResponse().getStatus(),
                result.getResponse().getContentAsString()
        );
    }

    private HttpTokenResponse refresh(String refreshToken) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/v1/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"refreshToken":"%s"}
                                """.formatted(refreshToken)))
                .andReturn();
        return new HttpTokenResponse(
                result.getResponse().getStatus(),
                result.getResponse().getContentAsString()
        );
    }

    private int protectedStatus(String accessToken) {
        try {
            return mockMvc.perform(get("/api/v1/test/protected")
                            .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                    .andReturn().getResponse().getStatus();
        } catch (Exception exception) {
            throw new IllegalStateException("Protected endpoint verification failed", exception);
        }
    }

    private static TokenPair tokenPair(String responseBody) {
        return new TokenPair(
                JsonPath.read(responseBody, "$.accessToken"),
                JsonPath.read(responseBody, "$.refreshToken")
        );
    }

    private static List<HttpTokenResponse> runTogether(
            Callable<HttpTokenResponse> first,
            Callable<HttpTokenResponse> second
    ) throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(2);
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        try {
            Callable<HttpTokenResponse> synchronizedFirst = synchronizedCall(first, ready, start);
            Callable<HttpTokenResponse> synchronizedSecond = synchronizedCall(second, ready, start);
            Future<HttpTokenResponse> firstResult = executor.submit(synchronizedFirst);
            Future<HttpTokenResponse> secondResult = executor.submit(synchronizedSecond);
            assertThat(ready.await(10, TimeUnit.SECONDS)).isTrue();
            start.countDown();
            return List.of(
                    firstResult.get(30, TimeUnit.SECONDS),
                    secondResult.get(30, TimeUnit.SECONDS)
            );
        } finally {
            start.countDown();
            executor.shutdownNow();
        }
    }

    private static Callable<HttpTokenResponse> synchronizedCall(
            Callable<HttpTokenResponse> delegate,
            CountDownLatch ready,
            CountDownLatch start
    ) {
        return () -> {
            ready.countDown();
            if (!start.await(10, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Concurrent test did not start in time");
            }
            return delegate.call();
        };
    }

    private record HttpTokenResponse(int status, String body) {
        @Override
        public String toString() {
            return "HttpTokenResponse[status=%d, body=[REDACTED]]".formatted(status);
        }
    }

    private record TokenPair(String accessToken, String refreshToken) {
        @Override
        public String toString() {
            return "TokenPair[accessToken=[REDACTED], refreshToken=[REDACTED]]";
        }
    }
}
