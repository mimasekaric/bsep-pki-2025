package com.bsep.pki.controllers;

import com.bsep.pki.dtos.CertificateDetailsDTO;
import com.bsep.pki.dtos.CertificateIssueDTO;
import com.bsep.pki.dtos.requests.ApproveCsrDTO;
import com.bsep.pki.dtos.requests.CSRRequestDTO;
import com.bsep.pki.dtos.requests.RejectCsrDTO;
import com.bsep.pki.enums.UserRole;
import com.bsep.pki.exceptions.ResourceNotFoundException;
import com.bsep.pki.models.CSR;
import com.bsep.pki.models.User;
import com.bsep.pki.repositories.CSRRepository;
import com.bsep.pki.services.CSRService;
import com.bsep.pki.services.CertificateService;
import com.bsep.pki.services.UserService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import java.security.Principal;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/csr")
@RequiredArgsConstructor
public class CSRController {

    private final CertificateService certificateService;
    private final CSRService csrService;
    private final CSRRepository csrRepository;
    private final UserService userService;

    @PostMapping("/submit")
    @PreAuthorize("hasAuthority('ROLE_ORDINARY_USER')")
    public ResponseEntity<CSR> submitCsr(@RequestBody CSRRequestDTO dto, Principal principal) {

        String userEmail = principal.getName();

        CSR newCsr = csrService.submitCsr(dto, userEmail);
        return ResponseEntity.ok(newCsr);
    }

    @PostMapping("/{csrId}/approve")
    @PreAuthorize("hasAuthority('ROLE_CA_USER')")
    public ResponseEntity<CertificateDetailsDTO> approveCsr(
            @PathVariable Long csrId, @RequestBody ApproveCsrDTO approveCsrDTO
    ) throws Exception {
        CertificateDetailsDTO issuedCert = certificateService.issueCertificateFromCsr(csrId, approveCsrDTO);
        return ResponseEntity.ok(issuedCert);
    }


    @GetMapping("/pending")
    @PreAuthorize("hasAuthority('ROLE_CA_USER')")
    public ResponseEntity<List<CSR>> getPendingCsrs(Principal principal) {
        String adminEmail = principal.getName();
        User issuer = userService.findByEmail(adminEmail);
        UUID issuerId = issuer.getId();
        List<CSR> pendingCsrs = csrService.getPendingCsrs(issuerId);
        return ResponseEntity.ok(pendingCsrs);
    }

    @PostMapping("/{csrId}/reject")
    @PreAuthorize("hasAuthority('ROLE_CA_USER')")
    public ResponseEntity<CSR> rejectCsr(@PathVariable Long csrId, @RequestBody RejectCsrDTO dto) {
        CSR rejectedCsr = csrService.rejectCsr(csrId, dto.getRejectionReason());
        return ResponseEntity.ok(rejectedCsr);
    }
}