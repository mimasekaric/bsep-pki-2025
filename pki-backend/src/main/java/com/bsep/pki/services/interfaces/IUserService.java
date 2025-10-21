package com.bsep.pki.services.interfaces;

import com.bsep.pki.dtos.requests.UserRegistrationDTO;
import com.bsep.pki.dtos.responses.UserResponseDTO;
import com.bsep.pki.models.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.List;
import java.util.Optional;

public interface IUserService {
    UserResponseDTO registerUser(UserRegistrationDTO userRegistrationDTO);
    User findByEmail(String email);
    List<User> findPotentialCertificateSubjects();

}
