package com.bsep.pki.controllers;

import com.bsep.pki.dtos.PasswordEntryDTO;
import com.bsep.pki.dtos.requests.PasswordEntryRequestDTO;
import com.bsep.pki.dtos.SharePasswordDTO;
import com.bsep.pki.models.User; // Dodaj import za User model
import com.bsep.pki.services.PasswordManagerService;
import com.bsep.pki.services.UserService; // Dodaj import za UserService
import jakarta.servlet.http.HttpServletRequest; // I dalje ti treba za druge stvari, ali ne za token direktno
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication; // Dodaj import
import org.springframework.security.core.context.SecurityContextHolder; // Dodaj import
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional; // Dodaj import
import java.util.UUID;

@RestController
@RequestMapping("/api/password-manager")
@RequiredArgsConstructor
public class PasswordManagerController {

    private final PasswordManagerService passwordManagerService;
    private final UserService userService; // Dodaj UserService

    private String getUserEmailFromSecurityContext() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new SecurityException("User not authenticated.");
        }

        Object principal = authentication.getPrincipal();

        if (principal instanceof User) {
            return ((User) principal).getEmail();
        } else if (principal instanceof org.springframework.security.core.userdetails.User) {

            return ((org.springframework.security.core.userdetails.User) principal).getUsername();
        } else if (principal instanceof Jwt) {
            Jwt jwt = (Jwt) principal;
            String email = jwt.getSubject();
            if (email != null) {
                return email;
            }
            throw new SecurityException("Could not determine requesting user email from JWT 'sub' claim.");
        } else {
            throw new SecurityException("Could not determine requesting user email from principal type: " + principal.getClass().getName());
        }
    }

    @PostMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'CA_USER', 'END_ENTITY')")
    public ResponseEntity<PasswordEntryDTO> createPasswordEntry(
            HttpServletRequest request,
            @Valid @RequestBody PasswordEntryRequestDTO dto) {
        try {
            String email = getUserEmailFromSecurityContext();
            PasswordEntryDTO createdEntry = passwordManagerService.createPasswordEntry(email, dto);
            return new ResponseEntity<>(createdEntry, HttpStatus.CREATED);
        } catch (Exception e) {
            System.err.println("Error creating password entry: " + e.getMessage());
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'CA_USER', 'END_ENTITY')")
    public ResponseEntity<List<PasswordEntryDTO>> getUserPasswordEntries(HttpServletRequest request) {
        String email = getUserEmailFromSecurityContext();
        List<PasswordEntryDTO> entries = passwordManagerService.getUserPasswordEntries(email);
        return new ResponseEntity<>(entries, HttpStatus.OK);
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'CA_USER', 'END_ENTITY')")
    public ResponseEntity<PasswordEntryDTO> getPasswordEntryById(
            HttpServletRequest request,
            @PathVariable Long id) {
        try {
            String email = getUserEmailFromSecurityContext();
            PasswordEntryDTO entry = passwordManagerService.getPasswordEntryById(id, email);
            return new ResponseEntity<>(entry, HttpStatus.OK);
        } catch (Exception e) {
            System.err.println("Error getting password entry: " + e.getMessage());
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
    }

    @GetMapping("/{id}/encrypted-password")
    @PreAuthorize("hasAnyRole('ADMIN', 'CA_USER', 'END_ENTITY')")
    public ResponseEntity<String> getEncryptedPasswordForUser(
            HttpServletRequest request,
            @PathVariable Long id) {
        try {
            String userId = getUserEmailFromSecurityContext(); // Koristi novu metodu
            String encryptedPassword = passwordManagerService.getEncryptedPasswordForUser(id, userId);
            return new ResponseEntity<>(encryptedPassword, HttpStatus.OK);
        } catch (Exception e) {
            System.err.println("Error getting encrypted password: " + e.getMessage());
            return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        }
    }

    @PostMapping("/{id}/share")
    @PreAuthorize("hasAnyRole('ADMIN', 'CA_USER', 'END_ENTITY')")
    public ResponseEntity<PasswordEntryDTO> sharePasswordEntry(
            HttpServletRequest request,
            @PathVariable Long id,
            @Valid @RequestBody SharePasswordDTO dto) {
        try {
            String ownerEmail = getUserEmailFromSecurityContext();
            PasswordEntryDTO updatedEntry = passwordManagerService.sharePasswordEntry(id, ownerEmail, dto);
            return new ResponseEntity<>(updatedEntry, HttpStatus.OK);
        } catch (Exception e) {
            System.err.println("Error sharing password entry: " + e.getMessage());
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'CA_USER', 'END_ENTITY')")
    public ResponseEntity<Void> deletePasswordEntry(
            HttpServletRequest request,
            @PathVariable Long id) {
        try {
            String mail = getUserEmailFromSecurityContext();
            passwordManagerService.deletePasswordEntry(id, mail);
            return new ResponseEntity<>(HttpStatus.NO_CONTENT);
        } catch (Exception e) {
            System.err.println("Error deleting password entry: " + e.getMessage());
            return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        }
    }
}