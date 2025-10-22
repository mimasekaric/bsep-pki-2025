package com.bsep.pki.controllers;


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

import java.io.IOException;
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

            java.security.cert.Certificate[] certificateChain = certificateService.loadCertificateChainById(certificateId);

            if (certificateChain == null || certificateChain.length == 0) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
            }


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

    @GetMapping("/ca")
    public ResponseEntity<List<CertificateDetailsDTO>> getValidCaCertificates() {
        List<CertificateDetailsDTO> caCerts = certificateService.getValidCaCertificates();
        return ResponseEntity.ok(caCerts);
    }



    @GetMapping("/my-public-key")
    @PreAuthorize("hasAnyRole('ADMIN', 'CA_USER', 'END_ENTITY')")
    public ResponseEntity<?> getMyPublicKeyPem(Principal principal) {
        try {
            String userEmail = principal.getName();
            User user = userService.findByEmail(userEmail);
            String publicKeyPem = certificateService.getUserEndEntityPublicKeyPem(user.getId());
            return ResponseEntity.ok(publicKeyPem);
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }


    @GetMapping("/public-key/{email}")
    @PreAuthorize("hasAnyRole('ADMIN', 'CA_USER', 'END_ENTITY')")
    public ResponseEntity<?> getPublicKeyPemForUser(@PathVariable String email) {
        try {
            UUID userId = userService.getIdByUsername(email);
            String publicKeyPem = certificateService.getUserEndEntityPublicKeyPem(userId);
            return ResponseEntity.ok(publicKeyPem);
        } catch (IOException e) {
            return new ResponseEntity<>("Failed to convert public key to PEM.", HttpStatus.INTERNAL_SERVER_ERROR);
        } catch (Exception e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.NOT_FOUND);
        }
    }
}
