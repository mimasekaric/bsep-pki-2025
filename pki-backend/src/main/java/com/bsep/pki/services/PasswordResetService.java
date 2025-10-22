package com.bsep.pki.services;


import com.bsep.pki.events.OnPasswordResetRequestEvent;
import com.bsep.pki.exceptions.InvalidTokenException;
import com.bsep.pki.models.PasswordResetToken;
import com.bsep.pki.models.User;
import com.bsep.pki.repositories.UserRepository;
import com.bsep.pki.util.AuditLog;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class PasswordResetService {

    private final UserRepository userRepository;
    private final PasswordResetTokenService tokenService;
    private final PasswordEncoder passwordEncoder;
    private final ApplicationEventPublisher eventPublisher;

    public PasswordResetService(UserRepository userRepository,
                                PasswordResetTokenService tokenService,
                                PasswordEncoder passwordEncoder,
                                ApplicationEventPublisher eventPublisher) {
        this.userRepository = userRepository;
        this.tokenService = tokenService;
        this.passwordEncoder = passwordEncoder;
        this.eventPublisher = eventPublisher;
    }

    @AuditLog(action = "START_PASSWORD_RESET")
    public void initiatePasswordReset(String email) {
        userRepository.findByEmail(email)
                .ifPresent(user -> eventPublisher.publishEvent(new OnPasswordResetRequestEvent(user)));
    }

    @AuditLog(action = "FINALIZE_PASSWORD_RESET")
    public void finalizePasswordReset(String token, String newPassword) {
        PasswordResetToken resetToken = tokenService.findByToken(token)
                .orElseThrow(() -> new InvalidTokenException("Token je nevažeći."));

        if (resetToken.isExpired()) {
            tokenService.deleteToken(resetToken);
            throw new InvalidTokenException("Token je istekao.");
        }

        User user = resetToken.getUser();
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        tokenService.deleteToken(resetToken);
    }
}