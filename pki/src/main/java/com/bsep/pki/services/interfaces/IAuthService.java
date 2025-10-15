package com.bsep.pki.services.interfaces;

import com.bsep.pki.dtos.requests.LoginRequestDTO;
import com.bsep.pki.dtos.requests.UserRegistrationDTO;
import com.bsep.pki.dtos.responses.LoginResponseDTO;
import com.bsep.pki.dtos.responses.UserResponseDTO;
import org.springframework.http.ResponseEntity;

public interface IAuthService {
    ResponseEntity<UserResponseDTO> register(UserRegistrationDTO dto);
    ResponseEntity<LoginResponseDTO> login(LoginRequestDTO loginRequest);
}
