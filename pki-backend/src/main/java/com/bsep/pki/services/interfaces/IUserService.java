package com.bsep.pki.services.interfaces;

import com.bsep.pki.dtos.requests.CAUserRegistrationDTO;
import com.bsep.pki.dtos.requests.ChangePasswordDTO;
import com.bsep.pki.dtos.requests.UserRegistrationDTO;
import com.bsep.pki.dtos.responses.UserResponseDTO;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Optional;

public interface IUserService {
    UserResponseDTO registerUser(UserRegistrationDTO userRegistrationDTO);
    void changePassword(ChangePasswordDTO changePasswordDTO, String userEmail);
    UserResponseDTO createCAUser(CAUserRegistrationDTO caUserDTO, String adminEmail);


}
