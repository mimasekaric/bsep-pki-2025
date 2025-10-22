package com.bsep.pki.events;

import com.bsep.pki.models.PasswordResetToken;
import com.bsep.pki.models.User;
import com.bsep.pki.services.EmailService;
import com.bsep.pki.services.PasswordResetTokenService;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;

@Component
public class PasswordResetListener implements ApplicationListener<OnPasswordResetRequestEvent> {

    private final PasswordResetTokenService tokenService;
    private final EmailService emailService;

    public PasswordResetListener(PasswordResetTokenService tokenService, EmailService emailService) {
        this.tokenService = tokenService;
        this.emailService = emailService;
    }

    @Override
    public void onApplicationEvent(OnPasswordResetRequestEvent event) {
        this.sendPasswordResetEmail(event);
    }

    private void sendPasswordResetEmail(OnPasswordResetRequestEvent event) {
        User user = event.getUser();
        PasswordResetToken token = tokenService.createPasswordResetToken(user);

        String recipientAddress = user.getEmail();
        String subject = "Zahtev za Oporavak Lozinke";
        String confirmationUrl = "https://localhost:4200/reset-password?token=" + token.getToken();
        String message = "Dobili smo zahtev za resetovanje Vaše lozinke. Kliknite na link ispod da biste postavili novu lozinku:\n" + confirmationUrl;

        emailService.sendEmail(recipientAddress, subject, message);
    }
}
