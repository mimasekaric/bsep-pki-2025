package com.bsep.pki.controllers;


import com.bsep.pki.dtos.IssuerDto;
import com.bsep.pki.enums.UserRole;
import com.bsep.pki.models.Certificate;
import com.bsep.pki.models.User;
import com.bsep.pki.repositories.UserRepository;
import com.bsep.pki.services.CertificateService;
import com.bsep.pki.dtos.CertificateDetailsDTO;
import com.bsep.pki.dtos.CertificateIssueDTO;
import com.bsep.pki.services.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/certificates")
@RequiredArgsConstructor
public class CertificateController {

    private final CertificateService certificateService;
    private final UserService userService;

    @PostMapping("/issue-root") // todo: dodati pre authorize
    public ResponseEntity<?> issueRoot(@RequestBody CertificateIssueDTO dto, Principal principal) {


        try {

            String adminEmail = principal.getName();
            User admin = userService.findByEmail(adminEmail);
            UUID adminId = admin.getId();

            Certificate cert = certificateService.issueRootCertificate(adminId, dto);
            return new ResponseEntity<>(new CertificateDetailsDTO(cert), HttpStatus.CREATED);

        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }

        /*try {

            String uuidString = "b667ae38-86aa-4004-b3d5-ddb3fbe50667";
            UUID adminId = UUID.fromString(uuidString);
            Certificate cert = certificateService.issueRootCertificate(adminId, dto);
            return new ResponseEntity<>(new CertificateDetailsDTO(cert), HttpStatus.CREATED);
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }*/
    }

    @PostMapping("/issue")
    //@PreAuthorize("hasAnyAuthority('ADMIN', 'CA_USER', 'ORDINARY_USER')")
    public ResponseEntity<?> issueCertificate(@RequestBody CertificateIssueDTO dto) {
        try {
            Object result = certificateService.issueCertificate(dto);
            return new ResponseEntity<>(result, HttpStatus.CREATED);
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }
    @GetMapping("/download/{certificateId}")
    public ResponseEntity<byte[]> downloadCertificate(@PathVariable Long certificateId) {
        try {
            // Load the complete certificate chain
            java.security.cert.Certificate[] certificateChain = certificateService.loadCertificateChainById(certificateId);

            if (certificateChain == null || certificateChain.length == 0) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
            }

            // Convert to PKCS#7 format which preserves hierarchy better
            byte[] pkcs7Bytes = certificateService.convertCertificateChainToPKCS7(certificateChain);

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"certificatechain" + certificateId + ".p7b\"")
                    .contentType(MediaType.valueOf("application/x-pkcs7-certificates"))
                    .body(pkcs7Bytes);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(null);
        }
    }

    @GetMapping("/issuers")
    // @PreAuthorize("hasAnyAuthority('ROLE_ADMIN', 'ROLE_CA', 'ROLE_USER')")
    public ResponseEntity<List<IssuerDto>> getAvailableIssuers() {
        List<IssuerDto> issuers = certificateService.getPotentialIssuers();
        return ResponseEntity.ok(issuers);
    }

    @GetMapping("/ca")
    public ResponseEntity<List<CertificateDetailsDTO>> getValidCaCertificates(Principal principal) {
        String ca_user_mail = principal.getName();
        User ca_user = userService.findByEmail(ca_user_mail);
        UUID userId = ca_user.getId();
        List<CertificateDetailsDTO> caCerts = certificateService.getValidCaCertificatesForUser(userId);
        return ResponseEntity.ok(caCerts);
    }


    @GetMapping("/adminCertificates")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<List<CertificateDetailsDTO>> getAllCertificates() {
        List<CertificateDetailsDTO> allCerts = certificateService.getAllCertificates();
        return ResponseEntity.ok(allCerts);
    }

    @GetMapping("/endEntityCertificates")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<List<CertificateDetailsDTO>> getUserEndEntityCertificates(
            Principal principal
    ) {

        User loggedInUser = userService.findByEmail(principal.getName());


        List<CertificateDetailsDTO> userCerts = certificateService.getEndEntityCertificatesForUser(loggedInUser.getId());
        return ResponseEntity.ok(userCerts);
    }
    @GetMapping("/caCertificates")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<List<CertificateDetailsDTO>> getCaCertificates(
            Principal principal
    ) {

        User loggedInUser = userService.findByEmail(principal.getName());


        List<CertificateDetailsDTO> userCerts = certificateService.getCaCertificatesForUser(loggedInUser.getId());
        return ResponseEntity.ok(userCerts);
    }
}
