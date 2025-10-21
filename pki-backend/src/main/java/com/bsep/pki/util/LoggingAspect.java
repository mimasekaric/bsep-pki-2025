package com.bsep.pki.util;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.UUID;

@Aspect
@Component
public class LoggingAspect {

    private static final Logger log = LoggerFactory.getLogger(LoggingAspect.class);

    @Around("@annotation(auditLog)")
    public Object logAround(ProceedingJoinPoint joinPoint, AuditLog auditLog) throws Throwable {
        long startTime = System.currentTimeMillis();

        // Postavljanje MDC (Mapped Diagnostic Context) za praćenje zahteva
        MDC.put("traceId", UUID.randomUUID().toString());
        MDC.put("action", auditLog.action());

        // Prikupljanje informacija za neporecivost
        String username = getUsername();
        String ipAddress = getClientIpAddress();
        MDC.put("username", username);
        MDC.put("ipAddress", ipAddress);

        log.info("Action '{}' started. Arguments: {}",
                auditLog.action(), Arrays.toString(joinPoint.getArgs()));

        Object result;
        try {
            result = joinPoint.proceed();
            long duration = System.currentTimeMillis() - startTime;
            MDC.put("durationMs", String.valueOf(duration));
            MDC.put("status", "SUCCESS");

            log.info("Action '{}' finished successfully. Duration: {}ms", auditLog.action(), duration);
            return result;
        } catch (Exception e) {
            long duration = System.currentTimeMillis() - startTime;
            MDC.put("durationMs", String.valueOf(duration));
            MDC.put("status", "FAILURE");
            MDC.put("error", e.getMessage());

            log.error("Action '{}' failed after {}ms. Error: {}",
                    auditLog.action(), duration, e.getMessage(), e);
            throw e;
        } finally {
            // Čišćenje MDC da ne bi "procureo" u druge threadove
            MDC.clear();
        }
    }

    private String getUsername() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof UserDetails) {
            return ((UserDetails) authentication.getPrincipal()).getUsername();
        }
        return "SYSTEM"; // ili "ANONYMOUS"
    }

    private String getClientIpAddress() {
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest();
        if (request != null) {
            String xfHeader = request.getHeader("X-Forwarded-For");
            if (xfHeader == null || xfHeader.isEmpty() || !xfHeader.contains(request.getRemoteAddr())) {
                return request.getRemoteAddr();
            }
            return xfHeader.split(",")[0];
        }
        return "UNKNOWN";
    }
}