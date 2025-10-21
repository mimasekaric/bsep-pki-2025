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
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import lombok.extern.slf4j.Slf4j;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
@AllArgsConstructor
@Slf4j
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
    public List<User> findPotentialCertificateSubjects() {
        log.info(">>> Pokrenuta metoda findPotentialCertificateSubjects.");

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            log.error("!!! Greška: Authentication objekat je null. Korisnik verovatno nije ulogovan.");
            return List.of();
        }

        String currentUserEmail = authentication.getName();
        log.info("1. Dobavljen email ulogovanog korisnika: '{}'", currentUserEmail);

        User currentUser;
        try {
            currentUser = userRepository.findByEmail(currentUserEmail)
                    .orElseThrow(() -> new RuntimeException("Korisnik nije pronađen."));
        } catch (RuntimeException e) {
            log.error("!!! Greška pri pronalaženju korisnika sa emailom: '{}'. Proverite da li postoji u bazi.", currentUserEmail);
            return List.of();
        }

        log.info("2. Uspešno pronađen ulogovani korisnik: ID={}, Email={}, Rola={}",
                currentUser.getId(), currentUser.getEmail(), currentUser.getRoleAsString());

        if (currentUser.getRole().equals(UserRole.ADMIN)) {
            log.info("3. Korisnik je ADMIN. Dohvatam sve korisnike iz baze.");

            List<User> allUsers = userRepository.findAll();
            log.info("   -> Pronađeno ukupno {} korisnika u bazi.", allUsers.size());


            log.info("<<< Završena metoda. Vraćam listu od {} korisnika.", allUsers.size());
            return allUsers;

        } else if (currentUser.getRole().equals(UserRole.CA_USER)) {
            log.info("3. Korisnik je CA_USER. Dohvatam korisnike iz organizacije '{}'.", currentUser.getOrganisation());

            if (currentUser.getOrganisation() == null || currentUser.getOrganisation().isBlank()) {
                log.warn("   -> Ulogovani CA_USER nema definisanu organizaciju. Vraćam praznu listu.");
                return List.of();
            }

            List<UserRole> rolesToFetch = List.of(UserRole.CA_USER, UserRole.ORDINARY_USER);
            log.info("   -> Traže se korisnici sa rolama: {}", rolesToFetch);

            List<User> usersInOrg = userRepository.findByOrganisationAndRoleIn(currentUser.getOrganisation(), rolesToFetch);
            log.info("   -> Pronađeno {} korisnika u organizaciji sa traženim rolama.", usersInOrg.size());

            return usersInOrg;
        }

        log.warn("4. Ulogovani korisnik nije ni ADMIN ni CA_USER. Rola: {}. Vraćam praznu listu.", currentUser.getRoleAsString());
        log.info("<<< Završena metoda. Vraćam praznu listu.");
        return List.of();
    }

}
