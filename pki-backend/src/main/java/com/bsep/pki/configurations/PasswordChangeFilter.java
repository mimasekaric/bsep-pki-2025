package com.bsep.pki.configurations; // Prilagodite paket

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.lang.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class PasswordChangeFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();


        if (authentication == null || !authentication.isAuthenticated() || !(authentication.getPrincipal() instanceof Jwt)) {
            filterChain.doFilter(request, response);
            return;
        }

        Jwt jwt = (Jwt) authentication.getPrincipal();
        Boolean mustChangePassword = jwt.getClaimAsBoolean("mustChangePassword");

        if (Boolean.TRUE.equals(mustChangePassword)) {


            String path = request.getRequestURI();
            if (isEndpointAllowed(path)) {
                filterChain.doFilter(request, response);
                return;
            }


            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\": \"Password change required\", \"message\": \"You must change your password before accessing this resource.\"}");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private boolean isEndpointAllowed(String path) {

        return path.equals("/api/users/change-password") ||
                path.equals("/api/auth/logout") || path.equals("/api/auth/login");
    }
}