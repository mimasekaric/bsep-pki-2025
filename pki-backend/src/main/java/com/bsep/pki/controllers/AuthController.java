package com.bsep.pki.controllers;

import com.bsep.pki.dtos.requests.ForgotPasswordRequest;
import com.bsep.pki.dtos.requests.LoginRequestDTO;
import com.bsep.pki.dtos.requests.ResetPasswordRequest;
import com.bsep.pki.dtos.requests.UserRegistrationDTO;
import com.bsep.pki.dtos.responses.LoginResponseDTO;
import com.bsep.pki.exceptions.InvalidTokenException;
import com.bsep.pki.services.PasswordResetService;
import com.bsep.pki.services.VerificationTokenService;
import com.bsep.pki.services.interfaces.IAuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final IAuthService authService;
    private final VerificationTokenService tokenService;
    private final PasswordResetService passwordResetService;

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


    @PostMapping("/forgot-password")
    public ResponseEntity<Void> forgotPassword(@RequestBody ForgotPasswordRequest request) {
        // Kontroler samo delegira poziv servisu.
        // Odgovor je uvek 200 OK da se ne bi otkrivalo postojanje emaila.
        passwordResetService.initiatePasswordReset(request.email());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@RequestBody ResetPasswordRequest request) {
        // Koristimo try-catch da bismo uhvatili greške iz servisnog sloja
        // i pretvorili ih u smislene HTTP odgovore.
        try {
            passwordResetService.finalizePasswordReset(request.token(), request.newPassword());
            return ResponseEntity.ok("Lozinka je uspešno resetovana.");
        } catch (InvalidTokenException e) {
            // Vraćamo poruku iz izuzetka klijentu.
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
}
