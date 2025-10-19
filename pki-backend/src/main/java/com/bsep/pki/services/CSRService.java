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
import org.bouncycastle.asn1.x509.Extensions;
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
            // Dekodiramo čisti Base64 string u niz bajtova
            byte[] csrBytes = Base64.decode(pemContent);

            // Kreiramo PKCS10CertificationRequest direktno iz bajtova
            return new PKCS10CertificationRequest(csrBytes);

        } catch (Exception e) {
            // Uhvatimo specifičnu grešku ako dekodiranje ne uspe
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

        // da li ima podataka o subjektu
        if (csr.getSubject().getRDNs().length == 0) {
            throw new IllegalArgumentException("CSR subject data is empty.");
        }
    }

    @Transactional
    public CSR submitCsr(CSRRequestDTO dto, String ownerEmail) {
        User owner = userRepository.findByEmail(ownerEmail)
                .orElseThrow(() -> new ResourceNotFoundException("User not found: " + ownerEmail));

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


}
