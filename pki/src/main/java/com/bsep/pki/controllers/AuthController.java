package com.bsep.pki.controllers;

import ch.qos.logback.core.net.SyslogOutputStream;
import com.bsep.pki.dtos.requests.LoginRequestDTO;
import com.bsep.pki.dtos.requests.UserRegistrationDTO;
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

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final IAuthService authService;
    private final VerificationTokenService tokenService;


    @PostMapping("/login")
    public ResponseEntity<LoginResponseDTO> login(@RequestBody LoginRequestDTO loginRequest) {
        return authService.login(loginRequest);
    }

    @PostMapping("/register")
    public ResponseEntity<UserResponseDTO> register(@RequestBody UserRegistrationDTO userRegistrationDTO) {
        return authService.register(userRegistrationDTO);
    }

    @GetMapping("/verify-email")
    public ResponseEntity<Void> verifyEmail(@RequestParam("token") String token) {
        String result = tokenService.validateVerificationToken(token);

        if (result.equals("valid")) {
            System.out.println("VERIFIKOVAO SE");
            return ResponseEntity.status(HttpStatus.FOUND)
//                    .location(URI.create("http://localhost:4200/login?verified=true"))
                    .build();
        } else {
            System.out.println("nije se vevriikovao");
            return ResponseEntity.status(HttpStatus.FOUND)
//                    .location(URI.create("http://localhost:4200/invalid-token?error=true"))
                    .build();
        }
    }
}
