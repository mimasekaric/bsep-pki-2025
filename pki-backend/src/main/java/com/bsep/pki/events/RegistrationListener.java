package com.bsep.pki.events;

import com.bsep.pki.models.User;
import com.bsep.pki.models.VerificationToken;
import com.bsep.pki.services.EmailService;
import com.bsep.pki.services.VerificationTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
public class RegistrationListener implements ApplicationListener<OnRegistrationCompletedEvent> {

    @Autowired
    private VerificationTokenService tokenService;

    @Autowired
    private EmailService emailService;

    @Override
    public void onApplicationEvent(OnRegistrationCompletedEvent event) {
        this.confirmRegistration(event);
    }

    private void confirmRegistration(OnRegistrationCompletedEvent event) {
        User user = event.getUser();

        VerificationToken verificationToken = tokenService.createVerificationTokenWithExpiry(user);

        String oldToken = UUID.randomUUID().toString();
        tokenService.createVerificationToken(user, oldToken);

        String recipientAddress = user.getEmail();
        String subject = "Email Verification";
        String confirmationUrl = "https://localhost:4200/verify-email?token=" + verificationToken.getToken();
        String message = "Click the link to verify your email: " + confirmationUrl;

        emailService.sendEmail(recipientAddress, subject, message);
    }
}
