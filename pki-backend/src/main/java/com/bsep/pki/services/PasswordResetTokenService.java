package com.bsep.pki.services;

import com.bsep.pki.models.PasswordResetToken;
import com.bsep.pki.models.User;
import com.bsep.pki.repositories.PasswordResetTokenRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.Optional;

@Service
@Transactional
public class PasswordResetTokenService {

    private final PasswordResetTokenRepository tokenRepository;

    public PasswordResetTokenService(PasswordResetTokenRepository tokenRepository) {
        this.tokenRepository = tokenRepository;
    }

    public PasswordResetToken createPasswordResetToken(User user) {
        Optional<PasswordResetToken> existingTokenOpt = tokenRepository.findByUser(user);

        if (existingTokenOpt.isPresent()) {
            tokenRepository.delete(existingTokenOpt.get());
            tokenRepository.flush();
        }

        PasswordResetToken newToken = new PasswordResetToken(user);
        return tokenRepository.save(newToken);
    }
    public Optional<PasswordResetToken> findByToken(String token) {
        return tokenRepository.findByToken(token);
    }

    public void deleteToken(PasswordResetToken token) {
        tokenRepository.delete(token);
    }
}
