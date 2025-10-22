package com.bsep.pki.controllers;

import com.bsep.pki.dtos.TemplateCreateDTO;
import com.bsep.pki.dtos.TemplateInfoDTO;
import com.bsep.pki.services.CertificateTemplateService;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/templates")
@AllArgsConstructor
public class CertificateTemplateController {

    private final CertificateTemplateService templateService;

    @PostMapping
    public ResponseEntity<String> createTemplate(@RequestBody TemplateCreateDTO dto, @AuthenticationPrincipal Jwt jwt) {
        String ownerEmail = jwt.getSubject();
        templateService.createTemplate(dto, ownerEmail);
        return new ResponseEntity<>("Certificate template created successfully.", HttpStatus.CREATED);
    }

    @GetMapping("/my-templates")
    public ResponseEntity<List<TemplateInfoDTO>> getMyTemplates(@AuthenticationPrincipal Jwt jwt) {
        String ownerEmail = jwt.getSubject();
        List<TemplateInfoDTO> templates = templateService.getTemplatesForUser(ownerEmail);
        return ResponseEntity.ok(templates);
    }

    @GetMapping("/issuer/{issuerSerialNumber}")
    public ResponseEntity<List<TemplateInfoDTO>> getTemplatesByIssuer(@PathVariable String issuerSerialNumber) {
        List<TemplateInfoDTO> templates = templateService.getTemplatesForIssuer(issuerSerialNumber);
        return ResponseEntity.ok(templates);
    }
}