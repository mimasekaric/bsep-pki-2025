package com.bsep.pki.services;

import com.bsep.pki.exceptions.ResourceNotFoundException;
import com.bsep.pki.models.Certificate;

import com.bsep.pki.repositories.CertificateRepository;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;

@Service
@RequiredArgsConstructor
public class CrlService {

    private final CertificateRepository certificateRepository;
    private final KeystoreService keystoreService;
    private final CryptoService cryptoService;

    @Value("${crl.storage.path}")
    private String crlBasePath;

   public void regenerateCrl(String issuerSerial) throws Exception {
        Certificate issuerCertData = certificateRepository.findBySerialNumber(issuerSerial)
                .orElseThrow(() -> new ResourceNotFoundException("Issuer not found for CRL generation."));

        // Učitaj privatni ključ izdavaoca
        String password = cryptoService.decryptAES(issuerCertData.getKeystore().getEncryptedPassword());
        PrivateKey issuerPrivateKey = keystoreService.getPrivateKey(issuerCertData.getKeystore().getId(), password.toCharArray(), issuerCertData.getAlias());
        java.security.cert.Certificate[] chain = keystoreService.getCertificateChain(issuerCertData.getKeystore().getId(), password.toCharArray(), issuerCertData.getAlias());
        X509Certificate issuerX509 = (X509Certificate) chain[0];
        X500Name issuerX500Name = new X500Name(issuerX509.getSubjectX500Principal().getName());

        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuerX500Name, new Date());
        crlBuilder.setNextUpdate(new Date(System.currentTimeMillis() + 30L * 24 * 60 * 60 * 1000)); // Npr. 30 dana

        // Pronađi sve povučene sertifikate od ovog izdavaoca
        List<Certificate> revokedCerts = certificateRepository.findByIssuerSerialNumber(issuerSerial);
        for (Certificate cert : revokedCerts) {
            BigInteger serialNumberBigInteger = new BigInteger(cert.getSerialNumber());
            if (cert.isRevoked()) {
                crlBuilder.addCRLEntry(serialNumberBigInteger, Date.from(cert.getRevocationDate().toInstant(ZoneOffset.UTC)), 0);
            }
        }
/*CRL REASON KODOVI :
CRLReason.unspecified (0)
CRLReason.keyCompromise (1)
CRLReason.cACompromise (2)
CRLReason.affiliationChanged (3)
CRLReason.superseded (4)
CRLReason.cessationOfOperation (5)
CRLReason.certificateHold (6)
CRLReason.removeFromCRL (8)
CRLReason.privilegeWithdrawn (9)
CRLReason.aACompromise (10)*/

        // Potpiši CRL
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(issuerPrivateKey);
        X509CRL crl = new JcaX509CRLConverter().getCRL(crlBuilder.build(contentSigner));

        // Sačuvaj CRL na disk
        saveCrlToFile(crl, issuerSerial);
    }

    private void saveCrlToFile(X509CRL crl, String issuerSerial) throws Exception {
        File crlFile = new File(crlBasePath, issuerSerial + ".crl");
        crlFile.getParentFile().mkdirs();
        try (FileOutputStream fos = new FileOutputStream(crlFile)) {
            fos.write(crl.getEncoded());
        }
    }
}