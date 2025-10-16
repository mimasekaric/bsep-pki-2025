package com.bsep.pki.services;

import com.bsep.pki.models.User;
import com.bsep.pki.models.VerificationToken;
import com.bsep.pki.repositories.UserRepository;
import com.bsep.pki.repositories.VerificationTokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
public class VerificationTokenService {

    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private VerificationTokenRepository tokenRepository;

    public void createVerificationToken(User user, String token) {
        user.setVerificationToken(token);
        userRepository.save(user);
    }

    public VerificationToken createVerificationTokenWithExpiry(User user) {

        tokenRepository.deleteByUser_Id(user.getId());
        String token = UUID.randomUUID().toString();
        VerificationToken verificationToken = new VerificationToken(token, user);
        
        return tokenRepository.save(verificationToken);
    }

    public String validateVerificationToken(String token) {
        VerificationToken verificationToken = tokenRepository.findByToken(token)
            .orElse(null);
            
        if (verificationToken != null) {
            if (verificationToken.isExpired()) {

                tokenRepository.delete(verificationToken);
                return "expired";
            }
            
            if (verificationToken.isUsed()) {
                return "already_used";
            }
            

            verificationToken.setUsed(true);
            tokenRepository.save(verificationToken);
            User user = verificationToken.getUser();
            user.setEnabled(true);
            userRepository.save(user);
            
            return "valid";
        }
        

        User user = userRepository.findByVerificationToken(token).orElse(null);
        if (user == null) {
            return "invalid";
        }

        user.setEnabled(true);
        userRepository.save(user);
        return "valid";
    }

    public void deleteExpiredTokens() {
        tokenRepository.findAll().stream()
            .filter(VerificationToken::isExpired)
            .forEach(tokenRepository::delete);
    }
}
