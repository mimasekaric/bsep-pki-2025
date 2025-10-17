package com.bsep.pki.services;

import com.bsep.pki.models.User;
import com.bsep.pki.repositories.CSRRepository;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.springframework.stereotype.Service;

import java.io.StringReader;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

@Service
@RequiredArgsConstructor
public class CSRService {

    private final CSRRepository csrRepository;

    // Metoda za parsiranje CSR-a iz PEM stringa
    public PKCS10CertificationRequest parseCsr(String pem) throws Exception {
        try (PemReader pemReader = new PemReader(new StringReader(pem))) {
            PemObject pemObject = pemReader.readPemObject();
            if (pemObject == null || !pemObject.getType().equalsIgnoreCase("CERTIFICATE REQUEST")) {
                throw new IllegalArgumentException("PEM content is not a valid Certificate Request.");
            }
            return new PKCS10CertificationRequest(pemObject.getContent());
        }
    }

    // Metoda za validaciju CSR-a
    public void validateCsr(PKCS10CertificationRequest csr) throws Exception {
        // 1. Provera digitalnog potpisa na CSR-u
        // Ovo potvrđuje da je vlasnik privatnog ključa zaista kreirao ovaj zahtev.
        JcaPKCS10CertificationRequest jcaCsr = new JcaPKCS10CertificationRequest(csr);
        PublicKey publicKey = jcaCsr.getPublicKey();

        if (!jcaCsr.isSignatureValid(new JcaContentVerifierProviderBuilder().build(publicKey))) {
            throw new SecurityException("CSR signature is invalid!");
        }

        // 2. Provera jačine javnog ključa (primer za RSA)
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

        // TODO: Provera ekstenzija koje je korisnik eventualno poslao u CSR-u.
        // Za sada preskačemo, jer ćemo mi dodati ekstenzije.
    }
}
