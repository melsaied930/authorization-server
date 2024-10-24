package com.example.authorization_server;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class OAuth2TokenTest {

    @Autowired
    private MockMvc mockMvc;

    @BeforeEach
    public void setup() {
        // Any setup before tests if necessary
    }

    @Test
    public void shouldReturnJwtTokenForClientCredentialsGrant() throws Exception {
        // Send POST request to /oauth2/token
        MvcResult result = mockMvc.perform(post("/oauth2/token")
                        .with(httpBasic("client-id", "client-secret"))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "client_credentials")
                        .param("scope", "read write"))
                .andExpect(status().isOk())
                .andReturn();

        // Extract JSON response
        String responseContent = result.getResponse().getContentAsString();

        // Parse the response to JSON
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonResponse = objectMapper.readTree(responseContent);

        // Assert the response contains an access_token and is a valid JWT
        assertThat(jsonResponse.has("access_token")).isTrue();
        assertThat(jsonResponse.get("access_token").asText()).startsWith("ey"); // JWT tokens usually start with "ey"

        // Validate the token format (e.g., ensure it's a JWT token by checking the number of parts)
        String jwtToken = jsonResponse.get("access_token").asText();
        String[] jwtParts = jwtToken.split("\\.");
        assertThat(jwtParts.length).isEqualTo(3); // JWT consists of 3 parts: header, payload, and signature
    }
}
