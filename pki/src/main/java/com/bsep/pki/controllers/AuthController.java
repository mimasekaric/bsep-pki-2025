package com.bsep.pki.controllers;

import com.bsep.pki.dtos.requests.LoginRequestDTO;
import com.bsep.pki.dtos.requests.UserRegistrationDTO;
import com.bsep.pki.dtos.responses.LoginResponseDTO;
import com.bsep.pki.dtos.responses.UserResponseDTO;
import com.bsep.pki.services.interfaces.IAuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static IAuthService authService;
    public AuthController(IAuthService authService) {
        AuthController.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDTO> login(@RequestBody LoginRequestDTO loginRequest) {
        return authService.login(loginRequest);
    }

    @PostMapping("/register")
    public ResponseEntity<UserResponseDTO> register(@RequestBody UserRegistrationDTO userRegistrationDTO) {
        return authService.register(userRegistrationDTO);
    }
}
