package com.esprit.userManagement.service;

import com.esprit.userManagement.dto.UserDTO;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;

@Service
public class KeycloakService {

    @Value("${keycloak.auth-server-url}")
    private String keycloakUrl;

    @Value("${keycloak.realm}")
    private String realm;


    @Value("${spring.security.oauth2.client.registration.keycloak.client-secret}")
    private String clientSecret;
    private final JwtDecoder jwtDecoder;  // Declare JwtDecoder

    public KeycloakService(JwtDecoder jwtDecoder) {
        this.jwtDecoder = jwtDecoder;  // Initialize the JwtDecoder
    }

    private final RestTemplate restTemplate = new RestTemplate();

    public String getToken(String username, String password) {
        String tokenUrl = keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/token";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "password");
        body.add("client_id", "spring-boot-client"); // Ensure this matches the Keycloak Client ID
        body.add("username", username);
        body.add("password", password);

        // If your client is confidential, you MUST send client_secret
        if (clientSecret != null && !clientSecret.isEmpty()) {
            body.add("client_secret", clientSecret);
        }

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
        RestTemplate restTemplate = new RestTemplate();

        try {
            ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);
            if (response.getStatusCode().is2xxSuccessful()) {
                return (String) response.getBody().get("access_token");
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to retrieve token: " + e.getMessage());
        }

        return null;
    }




    public boolean isTokenExpired(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            Instant now = Instant.now();
            // Check if the token is expired by comparing expiration with current time
            return jwt.getExpiresAt().isBefore(now);
        } catch (Exception e) {
            throw new RuntimeException("Error decoding JWT token", e);
        }
    }


    // Method to refresh the token
    public String refreshToken(String refreshToken) {
        String tokenUrl = keycloakUrl + "/realms/" + realm + "/protocol/openid-connect/token";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "refresh_token");
        body.add("client_id", "spring-boot-client");
        body.add("refresh_token", refreshToken);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        RestTemplate restTemplate = new RestTemplate();
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);

        if (response.getStatusCode().is2xxSuccessful()) {
            return (String) response.getBody().get("access_token");
        } else {
            throw new RuntimeException("Failed to refresh token: " + response.getStatusCode());
        }
    }




}
