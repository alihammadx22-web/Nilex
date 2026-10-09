package com.nilex.grad.controller;

import com.nilex.grad.config.GoogleOAuthConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
        "google.oauth.client-id=local-test-client",
        "google.oauth.client-secret=local-test-secret"
})
@AutoConfigureMockMvc
class GoogleOAuthBrowserFlowIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ClientRegistrationRepository clientRegistrations;

    @Test
    void browserStartUsesGoogleOidcAndExactLocalCallback() throws Exception {
        ClientRegistration google = clientRegistrations.findByRegistrationId("google");
        assertThat(google.getRedirectUri()).isEqualTo(GoogleOAuthConfig.CALLBACK_URI);
        assertThat(google.getScopes()).contains("openid", "profile", "email");

        MvcResult result = mockMvc.perform(get("/oauth2/authorization/google"))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        String location = result.getResponse().getRedirectedUrl();
        assertThat(location).startsWith("https://accounts.google.com/");
        assertThat(location).contains("state=");
        assertThat(location).contains("redirect_uri=" + GoogleOAuthConfig.CALLBACK_URI);
        assertThat(location).contains("nonce=", "code_challenge=", "code_challenge_method=S256");
        assertThat(location).doesNotContain("accessToken", "refreshToken");
        assertThat(result.getRequest().getSession(false)).isNotNull();

        mockMvc.perform(get("/api/v1/users/me")
                        .session((MockHttpSession) result.getRequest().getSession(false)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void callbackWithForgedStateIsRejectedWithoutExchangingCode() throws Exception {
        MvcResult start = mockMvc.perform(get("/oauth2/authorization/google"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        mockMvc.perform(get("/login/oauth2/code/google")
                        .session((MockHttpSession) start.getRequest().getSession(false))
                        .param("code", "not-a-google-code")
                        .param("state", "forged-state"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHORIZED"))
                .andExpect(jsonPath("$.accessToken").doesNotExist());
    }
}
