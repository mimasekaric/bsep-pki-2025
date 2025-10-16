package com.bsep.pki.controllers;

import ch.qos.logback.core.net.SyslogOutputStream;
import com.bsep.pki.dtos.requests.LoginRequestDTO;
import com.bsep.pki.dtos.requests.UserRegistrationDTO;
import com.bsep.pki.dtos.requests.CAUserRegistrationDTO;
import com.bsep.pki.dtos.requests.ChangePasswordDTO;
import com.bsep.pki.dtos.responses.LoginResponseDTO;
import com.bsep.pki.dtos.responses.UserResponseDTO;
import com.bsep.pki.services.VerificationTokenService;
import com.bsep.pki.services.interfaces.IAuthService;
import com.bsep.pki.services.interfaces.IUserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import org.springframework.security.core.Authentication;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final IAuthService authService;
    private final VerificationTokenService tokenService;
    private final IUserService userService;


    @PostMapping("/login")
    public ResponseEntity<LoginResponseDTO> login(@RequestBody LoginRequestDTO loginRequest) {
        return authService.login(loginRequest);
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody UserRegistrationDTO userRegistrationDTO) {
        try {
            return authService.register(userRegistrationDTO);
        } catch (RuntimeException e) {
            Map<String, String> error = new HashMap<>();
            error.put("status", "error");
            error.put("message", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }

    @GetMapping("/verify-email")
    public ResponseEntity<Map<String, String>> verifyEmail(@RequestParam("token") String token) {
        String result = tokenService.validateVerificationToken(token);
        
        Map<String, String> response = new HashMap<>();
        
        switch (result) {
            case "valid":
                response.put("status", "success");
                response.put("message", "Email uspešno verifikovan!");
                return ResponseEntity.ok(response);
                
            case "expired":
                response.put("status", "error");
                response.put("message", "Aktivacioni link je istekao. Molimo registrujte se ponovo.");
                return ResponseEntity.badRequest().body(response);
                
            case "already_used":
                response.put("status", "error");
                response.put("message", "Aktivacioni link je već korišćen.");
                return ResponseEntity.badRequest().body(response);
                
            case "invalid":
            default:
                response.put("status", "error");
                response.put("message", "Neispravan aktivacioni link.");
                return ResponseEntity.badRequest().body(response);
        }
    }

    @PostMapping("/create-ca-user")
    public ResponseEntity<?> createCAUser(@RequestBody CAUserRegistrationDTO caUserDTO, 
                                         Authentication authentication) {
        try {
            String adminEmail = authentication.getName();
            UserResponseDTO caUser = userService.createCAUser(caUserDTO, adminEmail);
            return ResponseEntity.ok(caUser);
        } catch (RuntimeException e) {
            Map<String, String> error = new HashMap<>();
            error.put("status", "error");
            error.put("message", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }

    @PostMapping("/change-password")
    public ResponseEntity<?> changePassword(@RequestBody ChangePasswordDTO changePasswordDTO,
                                          Authentication authentication) {
        try {
            String userEmail = authentication.getName();
            userService.changePassword(changePasswordDTO, userEmail);
            
            Map<String, String> response = new HashMap<>();
            response.put("status", "success");
            response.put("message", "Password changed successfully");
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            Map<String, String> error = new HashMap<>();
            error.put("status", "error");
            error.put("message", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }
}
