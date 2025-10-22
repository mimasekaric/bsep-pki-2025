package com.bsep.pki.services;

import com.bsep.pki.models.ActiveSession;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class SessionService {
    private final Map<String, ActiveSession> activeSessions = new ConcurrentHashMap<>();

    public void registerSession(String token, String email, String device, String ip) {
        activeSessions.put(token, new ActiveSession(token, email, device, ip));
    }

    public List<ActiveSession> getSessionsForUser(String email) {
        return activeSessions.values().stream()
                .filter(s -> s.getEmail().equals(email))
                .toList();
    }
    public ActiveSession getSession(String token) {
        return activeSessions.get(token);
    }

    public void revokeSession(String token) {
        activeSessions.remove(token);
    }

    public void revokeAllOtherSessions(String email, String currentToken) {
        activeSessions.entrySet().removeIf(e ->
                e.getValue().getEmail().equals(email) && !e.getKey().equals(currentToken));
    }

    public boolean isSessionActive(String token) {
        return activeSessions.containsKey(token);
    }

    public void deactivateAllCurrentSessionsForUser(String email){
        getSessionsForUser(email).stream().forEach(s -> s.setCurrent(false));
    }
}
