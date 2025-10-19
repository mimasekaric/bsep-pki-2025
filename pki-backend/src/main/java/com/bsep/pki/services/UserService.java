package com.bsep.pki.services;

import com.bsep.pki.dtos.requests.UserRegistrationDTO;
import com.bsep.pki.dtos.responses.UserResponseDTO;
import com.bsep.pki.enums.UserRole;
import com.bsep.pki.events.OnRegistrationCompletedEvent;
import com.bsep.pki.exceptions.ResourceNotFoundException;
import com.bsep.pki.mappers.UserMapper;
import com.bsep.pki.models.User;
import com.bsep.pki.repositories.UserRepository;
import com.bsep.pki.services.interfaces.IUserService;
import jakarta.persistence.EntityNotFoundException;
import jakarta.transaction.Transactional;
import jakarta.validation.constraints.Email;
import lombok.AllArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@AllArgsConstructor
public class UserService implements IUserService, UserDetailsService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserMapper userMapper;
    private final ApplicationEventPublisher eventPublisher;

    @Override
    @Transactional
    public UserResponseDTO registerUser(UserRegistrationDTO userRegistrationDTO) {
        Optional<User> existingUser = userRepository.findByEmail(userRegistrationDTO.getEmail());

        if (existingUser.isPresent()) {
            throw new RuntimeException(
                    String.format("User with email '%s' already exists!", userRegistrationDTO.getEmail())
            );
        }

        User newUser = userMapper.toEntity(userRegistrationDTO);

        newUser.setEnabled(false);
        newUser.setPassword(passwordEncoder.encode(userRegistrationDTO.getPassword()));
        newUser.setRole(UserRole.ORDINARY_USER);

        User savedUser = userRepository.save(newUser);

        eventPublisher.publishEvent(new OnRegistrationCompletedEvent(newUser));
        return userMapper.toDto(savedUser);
    }

public  Optional<User> getUserByUsername(String username) {
        Optional<User> user = userRepository.findByEmail(username);
        return user;
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
                user.isEnabled(),
                true,
                true,
                true,
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + user.getRole().name()))
        );
    }
    @Override
    public User findByEmail(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + email));
    }

    @Override
    public List<UserResponseDTO> findUsersByRole(UserRole role) {
            List<User> users = userRepository.findByRole(role);

        return users.stream()
                .map(userMapper::toDto)
                .collect(Collectors.toList());

    }

}
