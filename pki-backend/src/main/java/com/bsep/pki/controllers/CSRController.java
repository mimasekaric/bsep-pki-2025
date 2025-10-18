package com.bsep.pki.controllers;

import com.bsep.pki.dtos.CertificateDetailsDTO;
import com.bsep.pki.dtos.CertificateIssueDTO;
import com.bsep.pki.dtos.requests.ApproveCsrDTO;
import com.bsep.pki.dtos.requests.CSRRequestDTO;
import com.bsep.pki.models.CSR;
import com.bsep.pki.services.CSRService;
import com.bsep.pki.services.CertificateService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.security.Principal;

@RestController
@RequestMapping("/api/csr")
@RequiredArgsConstructor
public class CSRController {

    private final CertificateService certificateService;
    private final CSRService csrService;

    @PostMapping("/submit")
    public ResponseEntity<CSR> submitCsr(@RequestBody CSRRequestDTO dto, Principal principal) {

        String userEmail = principal.getName();

        CSR newCsr = csrService.submitCsr(dto, userEmail);
        return ResponseEntity.ok(newCsr);
    }

    @PostMapping("/{csrId}/approve")
    public ResponseEntity<CertificateDetailsDTO> approveCsr(
            @PathVariable Long csrId,
            @RequestBody ApproveCsrDTO dto // <-- KORISTIMO NOVI DTO
    ) throws Exception {
        CertificateDetailsDTO issuedCert = certificateService.issueCertificateFromCsr(csrId, dto);
        return ResponseEntity.ok(issuedCert);
    }
}