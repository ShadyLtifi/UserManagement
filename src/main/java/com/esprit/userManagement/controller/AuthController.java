package com.esprit.userManagement.controller;

import com.esprit.userManagement.dto.LoginRequest;
import com.esprit.userManagement.service.KeycloakService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
@CrossOrigin(origins = "http://localhost:4200")
public class AuthController {

    private final KeycloakService keycloakService;

    private final RestTemplate restTemplate = new RestTemplate();
    private final String keycloakUrl = "http://localhost:8888";  // Mettez l'URL correcte de Keycloak
    private final String realm = "gestion-utilisateur";  // Mettez le bon realm
    private final String adminUsername = "admin"; // Nom d'utilisateur admin de Keycloak
    private final String adminPassword = "admin"; // Mot de passe admin
    private final String clientId = "admin-cli"; // Client utilisé pour obtenir un token

    public AuthController(KeycloakService keycloakService) {
        this.keycloakService = keycloakService;
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody LoginRequest loginRequest) {
        try {
            String token = keycloakService.getToken(loginRequest.getUsername(), loginRequest.getPassword());

            // ✅ Return the token as a JSON response
            Map<String, String> response = new HashMap<>();
            response.put("access_token", token);

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid credentials or token expired."));
        }
    }


    @PostMapping("/refresh-token")
    public String refreshToken(@RequestParam String refreshToken) {
        return keycloakService.refreshToken(refreshToken);
    }

    @GetMapping("/validate-token")
    public boolean validateToken(@RequestParam String token) {
        return keycloakService.isTokenExpired(token);
    }

    /**
     * Ajoute un nouvel utilisateur à Keycloak
     */
    @PostMapping("/addUser")
    public ResponseEntity<String> addUser(@RequestBody Map<String, Object> user) {
        try {
            // Obtenir le token admin
            String adminToken = getAdminToken();

            // Construire l'URL pour ajouter un utilisateur
            String url = keycloakUrl + "/admin/realms/" + realm + "/users";

            // Configurer les headers
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setBearerAuth(adminToken);

            // Construire la requête
            HttpEntity<Map<String, Object>> request = new HttpEntity<>(user, headers);

            // Envoyer la requête POST à Keycloak
            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.POST, request, String.class);

            if (response.getStatusCode().is2xxSuccessful()) {
                return ResponseEntity.ok("Utilisateur ajouté avec succès!");
            } else {
                return ResponseEntity.status(response.getStatusCode()).body("Erreur lors de l'ajout de l'utilisateur: " + response.getBody());
            }

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Erreur interne: " + e.getMessage());
        }
    }

    /**
     * Récupère un token admin pour interagir avec l'API Keycloak
     */
    private String getAdminToken() {
        String tokenUrl = keycloakUrl + "/realms/master/protocol/openid-connect/token";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "password");
        body.add("client_id", clientId);
        body.add("username", adminUsername);
        body.add("password", adminPassword);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);

        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, request, Map.class);

        if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
            return (String) response.getBody().get("access_token");
        } else {
            throw new RuntimeException("Échec de l'obtention du token admin");
        }
    }
}

