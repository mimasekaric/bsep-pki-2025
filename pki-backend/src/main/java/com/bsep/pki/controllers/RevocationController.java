package com.bsep.pki.controllers;


import com.bsep.pki.models.User;
import com.bsep.pki.services.AuthService;
import com.bsep.pki.services.CertificateService;
import com.bsep.pki.dtos.requests.RevocationRequestDTO;
import com.bsep.pki.services.UserService;
import lombok.RequiredArgsConstructor;
import org. springframework. security. core. Authentication;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/api/revoke")
@RequiredArgsConstructor
public class RevocationController {

    private final CertificateService certificateService;
    private final UserService userService;

    @PostMapping("/{serialNumber}")
    public ResponseEntity<?> revoke(@PathVariable String serialNumber, @RequestBody RevocationRequestDTO dto) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication == null || !authentication.isAuthenticated()) {
                // Ovo se ne bi trebalo desiti ako su security filteri pravilno konfigurisani za @Secured ili .anyRequest().authenticated()
                return ResponseEntity.status(401).body("User not authenticated.");
            }

            UUID requestingUserId;
            Object principal = authentication.getPrincipal();

            if (principal instanceof User) {
                requestingUserId = ((User) principal).getId(); // <--- OVDE DOBIJAŠ UUID
            } else {
                 Optional<User> u=userService.getUserByUsername(authentication.getName());
                // Za JWT, `authentication.getName()` često vraća username.
                requestingUserId=u.get().getId();
                //return ResponseEntity.status(403).body("Could not determine requesting user ID.");
            }

            certificateService.revokeCertificate(serialNumber, dto.getReason(), requestingUserId);
            return ResponseEntity.ok("Certificate and its chain have been revoked.");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}
