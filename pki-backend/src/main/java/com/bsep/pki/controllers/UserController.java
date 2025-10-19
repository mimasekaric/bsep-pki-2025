package com.bsep.pki.controllers;

import com.bsep.pki.dtos.responses.UserResponseDTO;
import com.bsep.pki.enums.UserRole;
import com.bsep.pki.services.interfaces.IUserService;
import lombok.RequiredArgsConstructor;
import org.mapstruct.control.MappingControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

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
}