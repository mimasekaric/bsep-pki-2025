package com.bsep.pki.controllers;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.io.FileInputStream;

@RestController
@RequestMapping("/api/crl")
@RequiredArgsConstructor
public class CrlController {
    private static final String APPLICATION_PKIX_CRL_VALUE = "application/pkix-crl";


    @Value("${crl.storage.path}")
    private String crlBasePath;

    @GetMapping("/{issuerSerial}")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<InputStreamResource> downloadCrl(@PathVariable String issuerSerial) {
        try {
            File crlFile = new File(crlBasePath, issuerSerial + ".crl");
            if (!crlFile.exists()) {
                return ResponseEntity.notFound().build();
            }

            InputStreamResource resource = new InputStreamResource(new FileInputStream(crlFile));

            return ResponseEntity.ok()
                    .contentType(MediaType.parseMediaType(APPLICATION_PKIX_CRL_VALUE))
                    .header("Content-Disposition", "attachment; filename=\"" + crlFile.getName() + "\"")
                    .body(resource);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }
}