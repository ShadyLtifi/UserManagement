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
        body.add("client_id", "spring-boot-client");
        body.add("username", username);
        body.add("password", password);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);

        if (response.getStatusCode().is2xxSuccessful()) {
            String accessToken = (String) response.getBody().get("access_token");

            // Check if the access token is expired
            if (isTokenExpired(accessToken)) {
                String refreshToken = (String) response.getBody().get("refresh_token");
                accessToken = refreshToken(refreshToken);  // Refresh token if expired
            }

            return accessToken;
        } else {
            throw new RuntimeException("Failed to retrieve token: " + response.getStatusCode());
        }
    }

    // Check if the token is expired
    public boolean isTokenExpired(String token) {
        try {
            // Use the injected jwtDecoder to decode the token
            Jwt jwt = jwtDecoder.decode(token);
            Instant now = Instant.now();
            // Check if the token is expired by comparing expiration with current time
            return jwt.getExpiresAt().isBefore(now);
        } catch (Exception e) {
            // Handle errors with decoding the JWT (invalid token)
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

        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);

        if (response.getStatusCode().is2xxSuccessful()) {
            return (String) response.getBody().get("access_token");
        } else {
            throw new RuntimeException("Failed to refresh token: " + response.getStatusCode());
        }
    }


    public List<UserDTO> getAllUsers(String accessToken) {
        String usersUrl = keycloakUrl + "/admin/realms/" + realm + "/users";

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);  // Add Bearer token for authorization

        HttpEntity<String> entity = new HttpEntity<>(headers);

        try {
            ResponseEntity<UserDTO[]> response = restTemplate.exchange(
                    usersUrl,
                    HttpMethod.GET,
                    entity,
                    UserDTO[].class
            );

            if (response.getStatusCode().is2xxSuccessful()) {
                return Arrays.asList(response.getBody());
            } else {
                throw new RuntimeException("Failed to fetch users: " + response.getStatusCode());
            }
        } catch (Exception e) {
            throw new RuntimeException("Error fetching users: " + e.getMessage(), e);
        }
    }

}
