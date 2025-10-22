package com.bsep.pki.configurations;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.context.annotation.Configuration;
import jakarta.annotation.PostConstruct;
import java.security.Security;

@Configuration
public class BouncyCastleConfig {
    @PostConstruct
    public void init() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
}
