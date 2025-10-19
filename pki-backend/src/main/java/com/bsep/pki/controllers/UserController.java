package com.bsep.pki.controllers;

import com.bsep.pki.dtos.requests.CAUserRegistrationDTO;
import com.bsep.pki.dtos.requests.ChangePasswordDTO;
import com.bsep.pki.dtos.responses.LoginResponseDTO;
import com.bsep.pki.dtos.responses.UserResponseDTO;
import com.bsep.pki.enums.UserRole;
import com.bsep.pki.services.interfaces.IUserService;
import lombok.RequiredArgsConstructor;
import org.mapstruct.control.MappingControl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final IUserService userService;

    @GetMapping("/ca")
    public ResponseEntity<List<UserResponseDTO>> getCaUsers() {
        List<UserResponseDTO> caUsers = userService.findUsersByRole(UserRole.CA_USER);
        return ResponseEntity.ok(caUsers);
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
    public ResponseEntity<LoginResponseDTO> changePasswordForCA(@RequestBody ChangePasswordDTO changePasswordDTO,
                                                           Authentication authentication) {
        try {
            String userEmail = authentication.getName();
            LoginResponseDTO response = userService.changePassword(changePasswordDTO, userEmail);
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(null);
        }
    }
}