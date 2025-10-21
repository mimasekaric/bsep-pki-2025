package com.bsep.pki.services;

import com.bsep.pki.dtos.requests.CSRRequestDTO;
import com.bsep.pki.enums.UserRole;
import com.bsep.pki.exceptions.ResourceNotFoundException;
import com.bsep.pki.models.User;
import com.bsep.pki.repositories.CSRRepository;
import com.bsep.pki.repositories.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.stereotype.Service;
import com.bsep.pki.models.CSR;

import java.io.StringReader;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class CSRService {

    private final CSRRepository csrRepository;
    private final UserRepository userRepository;


    public PKCS10CertificationRequest parseCsr(String pem) throws Exception {

        String pemContent = pem
                .replace("-----BEGIN CERTIFICATE REQUEST-----", "")
                .replace("-----END CERTIFICATE REQUEST-----", "")
                .replaceAll("\\s", "");

        try {

            byte[] csrBytes = Base64.decode(pemContent);
            return new PKCS10CertificationRequest(csrBytes);

        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid CSR PEM format: Failed to decode Base64 content.", e);
        }
    }

    public void validateCsr(PKCS10CertificationRequest csr) throws Exception {
        // digitalni potpis
        JcaPKCS10CertificationRequest jcaCsr = new JcaPKCS10CertificationRequest(csr);
        PublicKey publicKey = jcaCsr.getPublicKey();

        if (!jcaCsr.isSignatureValid(new JcaContentVerifierProviderBuilder().build(publicKey))) {
            throw new SecurityException("CSR signature is invalid!");
        }

        // jacina javnog kljuca
        if (publicKey instanceof RSAPublicKey) {
            RSAPublicKey rsaKey = (RSAPublicKey) publicKey;
            int keySize = rsaKey.getModulus().bitLength();
            if (keySize < 2048) {
                throw new SecurityException("RSA key size is less than 2048 bits. Found: " + keySize);
            }
        }

        X500Name subjectName = csr.getSubject();
        // da li ima podataka o subjektu
        if (csr.getSubject().getRDNs().length == 0) {
            throw new IllegalArgumentException("CSR subject data is empty.");
        }
        if (subjectName.getRDNs(BCStyle.CN).length == 0) {
            throw new IllegalArgumentException("CSR validation failed: Common Name (CN) is required.");
        }
        if (subjectName.getRDNs(BCStyle.O).length == 0) {
            throw new IllegalArgumentException("CSR validation failed: Organization (O) is required.");
        }
        if (subjectName.getRDNs(BCStyle.OU).length == 0) {
            throw new IllegalArgumentException("CSR validation failed: Organizational Unit (OU) is required.");
        }
        if (subjectName.getRDNs(BCStyle.C).length == 0) {
            throw new IllegalArgumentException("CSR validation failed: Country (C) is required.");
        }
        if (subjectName.getRDNs(BCStyle.EmailAddress).length == 0) {
            throw new IllegalArgumentException("CSR validation failed: Email Address is required.");
        }
    }

    @Transactional
    public CSR submitCsr(CSRRequestDTO dto, String ownerEmail) {
        User owner = userRepository.findByEmail(ownerEmail)
                .orElseThrow(() -> new ResourceNotFoundException("User not found: " + ownerEmail));

        if(owner.getRole()!=UserRole.ORDINARY_USER){
            throw new SecurityException("Only ordinary users can request csr via this method.");
        }

        User approver = userRepository.findById(dto.getApproverId())
                .orElseThrow(() -> new ResourceNotFoundException("Approver not found: " + dto.getApproverId()));

        if (approver.getRole() != UserRole.ADMIN && approver.getRole() != UserRole.CA_USER) {
            throw new IllegalArgumentException("Selected approver is not a CA user.");
        }

        try {

            parseCsr(dto.getPemContent());
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid CSR PEM format: " + e.getMessage());
        }

        if (dto.getApproverId() == null) {
            throw new IllegalArgumentException("Signing certificate serial number must be provided.");
        }
        if (dto.getRequestedValidFrom() == null || dto.getRequestedValidTo() == null) {
            throw new IllegalArgumentException("Validity period must be provided.");
        }
        if (dto.getRequestedValidFrom().isAfter(dto.getRequestedValidTo())) {
            throw new IllegalArgumentException("'Valid From' date must be before 'Valid To' date.");
        }



        CSR csr = new CSR();
        csr.setPemContent(dto.getPemContent());
        csr.setOwner(owner);
        csr.setStatus(CSR.CsrStatus.PENDING);
        csr.setCreatedAt(LocalDateTime.now());

        csr.setApproverId(dto.getApproverId());
        csr.setRequestedValidFrom(dto.getRequestedValidFrom());
        csr.setRequestedValidTo(dto.getRequestedValidTo());

        return csrRepository.save(csr);
    }

    public Extensions getExtensionsFromCsr(PKCS10CertificationRequest csr) {
        Attribute[] attributes = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        if (attributes == null || attributes.length == 0) {
            return null;
        }
        return Extensions.getInstance(attributes[0].getAttrValues().getObjectAt(0));
    }

    public List<CSR> getPendingCsrs(UUID approverId) {
        return csrRepository.findByApproverIdAndStatus(approverId, CSR.CsrStatus.PENDING);
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


    public void validateCsrExtensions(Extensions requestedExtensions, User owner) {
        if (requestedExtensions == null) {
            return;
        }

        UserRole userRole = owner.getRole();

        if (userRole != UserRole.ORDINARY_USER) {

            throw new SecurityException("Only ordinary users can submit CSRs via this method.");
        }


        Extension bcExtension = requestedExtensions.getExtension(Extension.basicConstraints);
        if (bcExtension != null) {
            BasicConstraints bc = BasicConstraints.getInstance(bcExtension.getParsedValue());
            if (bc.isCA()) {
                throw new SecurityException("CSR validation failed: End-entity user cannot request to be a CA.");
            }
        }

        Extension kuExtension = requestedExtensions.getExtension(Extension.keyUsage);
        if (kuExtension != null) {
            KeyUsage ku = KeyUsage.getInstance(kuExtension.getParsedValue());
            if (ku.hasUsages(KeyUsage.keyCertSign) || ku.hasUsages(KeyUsage.cRLSign)) {
                throw new SecurityException("CSR validation failed: End-entity user cannot request keyCertSign or cRLSign.");
            }
        }

        // TODO: Dodati za ExtendedKeyUsage i SANs.

    }


}
