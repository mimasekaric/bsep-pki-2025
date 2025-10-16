package com.bsep.pki.configurations;

import com.bsep.pki.services.VerificationTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@EnableScheduling
public class TokenCleanupScheduler {
    
    @Autowired
    private VerificationTokenService tokenService;
    
    // Pokreće se svakih 6 sati
    @Scheduled(fixedRate = 21600000)
    public void cleanupExpiredTokens() {
        tokenService.deleteExpiredTokens();
    }
}
