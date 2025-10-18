package com.bsep.pki.controllers;

import com.bsep.pki.dtos.CertificateDetailsDTO;
import com.bsep.pki.dtos.CertificateIssueDTO;
import com.bsep.pki.dtos.requests.ApproveCsrDTO;
import com.bsep.pki.dtos.requests.CSRRequestDTO;
import com.bsep.pki.dtos.requests.RejectCsrDTO;
import com.bsep.pki.exceptions.ResourceNotFoundException;
import com.bsep.pki.models.CSR;
import com.bsep.pki.repositories.CSRRepository;
import com.bsep.pki.services.CSRService;
import com.bsep.pki.services.CertificateService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import java.security.Principal;
import java.util.List;

@RestController
@RequestMapping("/api/csr")
@RequiredArgsConstructor
public class CSRController {

    private final CertificateService certificateService;
    private final CSRService csrService;
    private final CSRRepository csrRepository;

    @PostMapping("/submit")
    public ResponseEntity<CSR> submitCsr(@RequestBody CSRRequestDTO dto, Principal principal) {

        String userEmail = principal.getName();

        CSR newCsr = csrService.submitCsr(dto, userEmail);
        return ResponseEntity.ok(newCsr);
    }

    @PostMapping("/{csrId}/approve")
    public ResponseEntity<CertificateDetailsDTO> approveCsr(
            @PathVariable Long csrId
    ) throws Exception {
        CertificateDetailsDTO issuedCert = certificateService.issueCertificateFromCsr(csrId);
        return ResponseEntity.ok(issuedCert);
    }


    @Transactional
    public CSR rejectCsr(Long csrId, String reason) {
        CSR csr = csrRepository.findById(csrId)
                .orElseThrow(() -> new ResourceNotFoundException("CSR not found with ID: " + csrId));

        if (csr.getStatus() != CSR.CsrStatus.PENDING) {
            throw new IllegalStateException("Only pending CSRs can be rejected.");
        }
        if (reason == null || reason.isBlank()) {
            throw new IllegalArgumentException("Rejection reason cannot be empty.");
        }

        csr.setStatus(CSR.CsrStatus.REJECTED);
        csr.setRejectionReason(reason);
        return csrRepository.save(csr);
    }

    @GetMapping("/pending")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_CA_USER')") // Osigurajmo endpoint
    public ResponseEntity<List<CSR>> getPendingCsrs() {
        List<CSR> pendingCsrs = csrService.getPendingCsrs();
        return ResponseEntity.ok(pendingCsrs);
    }

    @PostMapping("/{csrId}/reject")
    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_CA_USER')")
    public ResponseEntity<CSR> rejectCsr(@PathVariable Long csrId, @RequestBody RejectCsrDTO dto) {
        CSR rejectedCsr = csrService.rejectCsr(csrId, dto.getRejectionReason());
        return ResponseEntity.ok(rejectedCsr);
    }
}