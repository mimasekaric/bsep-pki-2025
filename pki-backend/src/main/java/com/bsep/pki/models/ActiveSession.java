package com.bsep.pki.models;

import jakarta.persistence.Entity;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;


@AllArgsConstructor
@NoArgsConstructor
@Data
public class ActiveSession {
    private String token;
    private String email;
    private String device;
    private String ipAddress;
    private LocalDateTime lastActive;
    private boolean current;

    public ActiveSession(String token, String email, String device, String ipAddress) {
        this.token = token;
        this.email = email;
        this.device = device;
        this.ipAddress = ipAddress;
        this.lastActive = LocalDateTime.now();
        this.current = true;
    }

    public void updateLastActive() {
        this.lastActive = LocalDateTime.now();
    }


}
