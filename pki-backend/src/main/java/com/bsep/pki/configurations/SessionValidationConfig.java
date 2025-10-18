package com.bsep.pki.configurations;

import com.bsep.pki.services.SessionService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jwt.JwtDecoder; // I dalje ga injektujemo, ali može i bez njega
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component // Važno: Spring će ga prepoznati kao Bean
public class SessionValidationConfig extends OncePerRequestFilter {

    private final SessionService sessionService;
    private final JwtDecoder jwtDecoder;

    @Autowired // Spring će automatski injektovati zavisnosti
    public SessionValidationConfig(SessionService sessionService, JwtDecoder jwtDecoder) {
        this.sessionService = sessionService;
        this.jwtDecoder = jwtDecoder;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {


        if (request.getRequestURI().startsWith("/api/auth/login") ||
                request.getRequestURI().startsWith("/api/auth/register") ||
                request.getRequestURI().startsWith("/verify-email") ||
                request.getRequestURI().startsWith("/api/certificates")) {
            filterChain.doFilter(request, response);
            return;
        }

        String authHeader = request.getHeader("Authorization");
        String token = null;

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
        }

        if (token != null) {
            if (sessionService.getSession(token) == null) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("{\"error\": \"Session revoked or invalid.\"}");
                response.setContentType("application/json");
                return;
            }
        }
        filterChain.doFilter(request, response);
    }
}