package com.bsep.pki.services;

import com.bsep.pki.dtos.requests.CSRRequestDTO;
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

@Service
@RequiredArgsConstructor
public class CSRService {

    private final CSRRepository csrRepository;
    private final UserRepository userRepository;

    // Metoda za parsiranje CSR-a iz PEM stringa
    public PKCS10CertificationRequest parseCsr(String pem) throws Exception {

        String pemContent = pem
                .replace("-----BEGIN CERTIFICATE REQUEST-----", "")
                .replace("-----END CERTIFICATE REQUEST-----", "")
                .replaceAll("\\s", ""); // Uklonimo sve bele karaktere (razmake, \n, \r, itd.)

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

    // Metoda za validaciju CSR-a
    public void validateCsr(PKCS10CertificationRequest csr) throws Exception {
        // 1. Provera digitalnog potpisa
        JcaPKCS10CertificationRequest jcaCsr = new JcaPKCS10CertificationRequest(csr);
        PublicKey publicKey = jcaCsr.getPublicKey();

        if (!jcaCsr.isSignatureValid(new JcaContentVerifierProviderBuilder().build(publicKey))) {
            throw new SecurityException("CSR signature is invalid!");
        }

        // 2. Provera jačine javnog ključa
        if (publicKey instanceof RSAPublicKey) {
            RSAPublicKey rsaKey = (RSAPublicKey) publicKey;
            int keySize = rsaKey.getModulus().bitLength();
            if (keySize < 2048) {
                throw new SecurityException("RSA key size is less than 2048 bits. Found: " + keySize);
            }
        }

        // 3. Provera da li su podaci o subjektu prisutni
        if (csr.getSubject().getRDNs().length == 0) {
            throw new IllegalArgumentException("CSR subject data is empty.");
        }
    }

    @Transactional
    public CSR submitCsr(CSRRequestDTO dto, String ownerEmail) {
        User owner = userRepository.findByEmail(ownerEmail)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + ownerEmail));

        try {
            // Koristimo CsrService da validiramo da li je PEM uopšte validan pre čuvanja
            parseCsr(dto.getPemContent());
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid CSR PEM format: " + e.getMessage());
        }

        CSR csr = new CSR();
        csr.setPemContent(dto.getPemContent());
        csr.setOwner(owner);
        csr.setStatus(CSR.CsrStatus.PENDING);
        csr.setCreatedAt(LocalDateTime.now());

        return csrRepository.save(csr);
    }

    public Extensions getExtensionsFromCsr(PKCS10CertificationRequest csr) {
        Attribute[] attributes = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        if (attributes == null || attributes.length == 0) {
            return null;
        }
        return Extensions.getInstance(attributes[0].getAttrValues().getObjectAt(0));
    }



}
