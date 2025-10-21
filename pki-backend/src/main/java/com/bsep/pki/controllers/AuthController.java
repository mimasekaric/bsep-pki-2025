package com.bsep.pki.controllers;

import com.bsep.pki.dtos.requests.ForgotPasswordRequest;
import com.bsep.pki.dtos.requests.LoginRequestDTO;
import com.bsep.pki.dtos.requests.ResetPasswordRequest;
import com.bsep.pki.dtos.requests.UserRegistrationDTO;
import com.bsep.pki.dtos.responses.LoginResponseDTO;
import com.bsep.pki.dtos.responses.UserIdResponseDTO;
import com.bsep.pki.dtos.responses.UserOrganizationResponseDTO;
import com.bsep.pki.exceptions.InvalidTokenException;
import com.bsep.pki.services.PasswordResetService;
import com.bsep.pki.services.VerificationTokenService;
import com.bsep.pki.services.interfaces.IAuthService;
import com.bsep.pki.dtos.responses.UserResponseDTO;
import com.bsep.pki.models.ActiveSession;
import com.bsep.pki.models.User;
import com.bsep.pki.models.VerificationToken;
import com.bsep.pki.services.SessionService;
import com.bsep.pki.services.VerificationTokenService;
import com.bsep.pki.services.interfaces.IAuthService;
import com.bsep.pki.services.interfaces.IUserService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.web.bind.annotation.*;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final IAuthService authService;
    private final VerificationTokenService tokenService;
    private final PasswordResetService passwordResetService;
    private final SessionService sessionService;
    private final JwtDecoder jwtDecoder;
    private final IUserService userService;


    @PostMapping("/login")
    public ResponseEntity<LoginResponseDTO> login(@RequestBody LoginRequestDTO loginRequest,  HttpServletRequest request) {
        ResponseEntity<LoginResponseDTO> loginResponse =  authService.login(loginRequest);
        if (loginResponse.getStatusCode().is2xxSuccessful() && loginResponse.getBody() != null) {
            String token = loginResponse.getBody().getAccessToken();
            String email = loginRequest.getEmail();

            String ipAddress = request.getRemoteAddr();
            String device = request.getHeader("User-Agent");

            sessionService.deactivateAllCurrentSessionsForUser(email);
            sessionService.registerSession(token, email, device, ipAddress);
        }

        return loginResponse;
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
        passwordResetService.initiatePasswordReset(request.email());
        return ResponseEntity.ok().build();
    }

    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@RequestBody ResetPasswordRequest request) {
        try {
            passwordResetService.finalizePasswordReset(request.token(), request.newPassword());
            return ResponseEntity.ok("Lozinka je uspešno resetovana.");
        } catch (InvalidTokenException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }
    @GetMapping("/tokens/{email}")
    public ResponseEntity<?> getActiveSessions(@PathVariable String email) {
        List<ActiveSession> sessions = sessionService.getSessionsForUser(email);
        return ResponseEntity.ok(sessions);
    }
    @DeleteMapping("/tokensdelete/{email}")
    public ResponseEntity<Void> revokeAllOtherSessionsForUser(
            @PathVariable String email,
            @RequestHeader(name = "Authorization") String authHeader) {

        String currentToken = null;
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            currentToken = authHeader.substring(7);
        } else {
            return ResponseEntity.badRequest().build();
        }
        sessionService.revokeAllOtherSessions(email, currentToken);
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/revoke/{token}")
    public ResponseEntity<Void> revokeSession(@PathVariable String token) {
        sessionService.revokeSession(token);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/me")
    public ResponseEntity<UserIdResponseDTO> getCurrentUserId(@RequestHeader(name = "Authorization") String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        try {
            String token = authHeader.substring(7);
            Jwt decodedJwt = this.jwtDecoder.decode(token);

            String email = decodedJwt.getSubject();
            if (email == null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
            }

            User user = userService.findByEmail(email);

            if (user == null) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
            }

            UserIdResponseDTO response = new UserIdResponseDTO(user.getId());
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    @GetMapping("/my-organisation")
    public ResponseEntity<UserOrganizationResponseDTO> getCurrentUserOrganisation(@RequestHeader(name = "Authorization") String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        try {
            String token = authHeader.substring(7);
            Jwt decodedJwt = this.jwtDecoder.decode(token);

            String email = decodedJwt.getSubject();
            if (email == null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
            }

            User user = userService.findByEmail(email);

            if (user == null) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
            }

            UserOrganizationResponseDTO response = new UserOrganizationResponseDTO(user.getOrganisation());
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

}
