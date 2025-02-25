package com.esprit.userManagement.controller;

import com.esprit.userManagement.service.KeycloakService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/admin")
public class UserController {

    @Autowired
    private KeycloakService keycloakService;


    @GetMapping("/roles")
    @PreAuthorize("hasAuthority('ROLE_organisateur')")
    public String getRoles(@AuthenticationPrincipal Jwt jwt) {
        // Log the JWT claims for debugging
        System.out.println("🔍 JWT Claims: " + jwt.getClaims());

        // Extract roles from the JWT token directly
        List<String> roles = jwt.getClaimAsStringList("resource_access.spring-boot-client.roles");

        // If roles are not found under the client roles, check realm roles
        if (roles == null || roles.isEmpty()) {
            Map<String, Object> realmAccess = jwt.getClaim("realm_access");
            if (realmAccess != null && realmAccess.containsKey("roles")) {
                roles = (List<String>) realmAccess.get("roles");
            }
        }

        // If roles are found, return them as a string
        if (roles != null && !roles.isEmpty()) {
            return "Roles: " + String.join(", ", roles);
        } else {
            return "No roles found in the token";
        }
    }


    @GetMapping("/profile")
    @PreAuthorize("hasAuthority('ROLE_organisateur')")
    public Map<String, Object> getOrganisateurProfile(@AuthenticationPrincipal Jwt jwt) {
        String username = jwt.getClaimAsString("preferred_username");
        String email = jwt.getClaimAsString("email");
        String fullName = jwt.getClaimAsString("name");


        // Safely retrieve client roles from resource_access.spring-boot-client
        List<String> clientRoles = jwt.hasClaim("resource_access") &&
                jwt.getClaim("resource_access") instanceof Map resourceAccess &&
                resourceAccess.containsKey("spring-boot-client") &&
                resourceAccess.get("spring-boot-client") instanceof Map springBootClient &&
                springBootClient.containsKey("roles")
                ? (List<String>) springBootClient.get("roles")
                : List.of();

        // Construct the response map with null-safe values
        Map<String, Object> response = new HashMap<>();
        response.put("username", username != null ? username : "N/A");
        response.put("email", email != null ? email : "N/A");
        response.put("fullName", fullName != null ? fullName : "N/A");
        response.put("clientRoles", clientRoles);

        return response;
    }



}
