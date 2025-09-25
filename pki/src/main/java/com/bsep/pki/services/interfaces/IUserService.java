package com.bsep.pki.services.interfaces;

import com.bsep.pki.dtos.requests.UserRegistrationDTO;
import com.bsep.pki.dtos.responses.UserResponseDTO;
import org.springframework.security.core.userdetails.UserDetails;

public interface IUserService {
    UserResponseDTO registerUser(UserRegistrationDTO userRegistrationDTO);
}
