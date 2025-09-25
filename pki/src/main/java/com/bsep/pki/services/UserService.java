package com.bsep.pki.services;

import com.bsep.pki.dtos.requests.UserRegistrationDTO;
import com.bsep.pki.dtos.responses.UserResponseDTO;
import com.bsep.pki.enums.UserRole;
import com.bsep.pki.mappers.UserMapper;
import com.bsep.pki.models.User;
import com.bsep.pki.repositories.UserRepository;
import com.bsep.pki.services.interfaces.IUserService;
import jakarta.persistence.EntityNotFoundException;
import lombok.AllArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Optional;

@Service
@AllArgsConstructor
public class UserService implements IUserService, UserDetailsService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserMapper userMapper;

    @Override
    public UserResponseDTO registerUser(UserRegistrationDTO userRegistrationDTO) {
        Optional<User> existingUser = userRepository.findByEmail(userRegistrationDTO.getEmail());

        if (existingUser.isPresent()) {
            throw new EntityNotFoundException(
                    String.format("User with this email not foun")
            );
        }

        User newUser = userMapper.toEntity(userRegistrationDTO);

        newUser.setPassword(passwordEncoder.encode(userRegistrationDTO.getPassword()));
        newUser.setRole(UserRole.ORDINARY_USER);

        User savedUser = userRepository.save(newUser);

        return userMapper.toDto(savedUser);
    }


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(username)
                .orElseThrow(() -> new EntityNotFoundException(
                        String.format("User with username '%s' not found", username)
                ));

        return new org.springframework.security.core.userdetails.User(
                user.getEmail(),
                user.getPassword(),
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + user.getRole().name()))
        );
    }
}
