package com.bsep.pki.controllers;


import com.bsep.pki.models.Certificate;
import com.bsep.pki.services.CertificateService;
import com.bsep.pki.dtos.CertificateDetailsDTO;
import com.bsep.pki.dtos.CertificateIssueDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/certificates")
@RequiredArgsConstructor
public class CertificateController {

    private final CertificateService certificateService;

    @PostMapping("/issue-root") // todo: dodati pre authorize
    public ResponseEntity<?> issueRoot(@RequestBody CertificateIssueDTO dto) {
        try {
            // TODO: U realnoj aplikaciji, ID admina bi se dobio iz Spring Security Context-a
            String uuidString = "123e4567-e89b-12d3-a456-426614174000";
            UUID adminId = UUID.fromString(uuidString);
            Certificate cert = certificateService.issueRootCertificate(adminId, dto);
            return new ResponseEntity<>(new CertificateDetailsDTO(cert), HttpStatus.CREATED);
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("/issue")
    public ResponseEntity<?> issueCertificate(@RequestBody CertificateIssueDTO dto) {
        try {
            Certificate cert = certificateService.issueCertificate(dto);
            return new ResponseEntity<>(new CertificateDetailsDTO(cert), HttpStatus.CREATED);
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }
}
