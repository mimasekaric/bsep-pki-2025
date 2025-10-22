package com.bsep.pki.services;

import com.bsep.pki.dtos.PasswordEntryDTO;
import com.bsep.pki.dtos.requests.PasswordEntryRequestDTO;
import com.bsep.pki.dtos.SharePasswordDTO;
import com.bsep.pki.exceptions.ResourceNotFoundException;
import com.bsep.pki.models.Password;
import com.bsep.pki.models.User;
import com.bsep.pki.repositories.PasswordRepository;
import com.bsep.pki.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.PublicKey;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class PasswordManagerService {

    private final PasswordRepository passwordEntryRepository;
    private final UserRepository userRepository;
    private final CertificateService certificateService;
    private final UserService userService;
    private final CryptoService cryptoService;
    @Transactional
    public PasswordEntryDTO createPasswordEntry(String email, PasswordEntryRequestDTO dto) throws Exception {
        User owner = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + email));


        certificateService.getUserValidEndEntityCertificate(owner.getId());

        Password entry = new Password();
        entry.setOwner(owner);
        entry.setOwnerUsername(owner.getEmail());
        entry.setSiteName(dto.getSiteName());
        entry.setUsername(dto.getUsername());
        entry.setEncryptedPassword(dto.getEncryptedPassword());

        passwordEntryRepository.save(entry);
        return new PasswordEntryDTO(entry);
    }

    public List<PasswordEntryDTO> getUserPasswordEntries(String email) {

        User owner = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + email));



        List<Password> ownedEntries = passwordEntryRepository.findByOwnerUsername(email);
        List<Password> sharedEntries = passwordEntryRepository.findBySharedWithKey(owner.getId());



        List<PasswordEntryDTO> allEntries = ownedEntries.stream()
                .map(PasswordEntryDTO::new)
                .collect(Collectors.toList());

        sharedEntries.stream()
                .filter(entry -> !entry.getOwner().getEmail().equals(email)) // ako je user vlasnik onda mu ne dodajem
                .map(PasswordEntryDTO::new)
                .forEach(allEntries::add);

        return allEntries;
    }

    public PasswordEntryDTO getPasswordEntryById(Long entryId, String email) throws Exception {
        Password entry = passwordEntryRepository.findById(entryId)
                .orElseThrow(() -> new ResourceNotFoundException("Password entry not found with ID: " + entryId));
        User owner = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + email));

        if (!entry.getOwner().getEmail().equals(email) && !entry.getSharedWith().containsKey(owner.getId())) {
            throw new Exception("You are not authorized to access this password entry.");
        }
        return new PasswordEntryDTO(entry);
    }


    public String getEncryptedPasswordForUser(Long entryId, String email) throws Exception {
        Password entry = passwordEntryRepository.findById(entryId)
                .orElseThrow(() -> new ResourceNotFoundException("Password entry not found with ID: " + entryId));
        UUID issuerid= userService.getIdByUsername(email);
        if (entry.getOwner().getEmail().equals(email)) {
            return entry.getEncryptedPassword();
        } else if (entry.getSharedWith().containsKey(issuerid)) {
            return entry.getSharedWith().get(issuerid);
        } else {
            throw new Exception("You are not authorized to view this password entry.");
        }
    }


    @Transactional
    public PasswordEntryDTO sharePasswordEntry(Long entryId, String ownerName, SharePasswordDTO dto) throws Exception {
        Password entry = passwordEntryRepository.findById(entryId)
                .orElseThrow(() -> new ResourceNotFoundException("Password entry not found with ID: " + entryId));


        if (!entry.getOwner().getEmail().equals(ownerName)) {
            throw new Exception("Only the owner can share this password entry.");
        }


        User shareWithUser = userRepository.findByEmail(dto.getShareWithUserName())
                .orElseThrow(() -> new ResourceNotFoundException("User to share with not found with email: " + dto.getShareWithUserName()));


        certificateService.getUserValidEndEntityCertificate(shareWithUser.getId());


        entry.getSharedWith().put(shareWithUser.getId(), dto.getReEncryptedPassword());
        passwordEntryRepository.save(entry);

        return new PasswordEntryDTO(entry);
    }

    @Transactional
    public void deletePasswordEntry(Long entryId, String username) throws Exception {
        Password entry = passwordEntryRepository.findById(entryId)
                .orElseThrow(() -> new ResourceNotFoundException("Password entry not found with ID: " + entryId));


        if (!entry.getOwner().getEmail().equals(username)) {
            throw new Exception("Only the owner can delete this password entry.");
        }

        passwordEntryRepository.delete(entry);
    }

}