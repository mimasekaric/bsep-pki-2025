package com.bsep.pki.services;


import com.bsep.pki.dtos.CertificateDetailsDTO;
import com.bsep.pki.dtos.CertificateWithPrivateKeyDTO;
import com.bsep.pki.enums.CertificateType;
import com.bsep.pki.enums.UserRole;
import com.bsep.pki.models.*;
import com.bsep.pki.exceptions.CertificateValidationException;
import com.bsep.pki.exceptions.ResourceNotFoundException;
import com.bsep.pki.models.Certificate;
import com.bsep.pki.repositories.CSRRepository;
import com.bsep.pki.repositories.CertificateRepository;
import com.bsep.pki.repositories.KeystoreRepository;
import com.bsep.pki.repositories.UserRepository;
import com.bsep.pki.dtos.CertificateIssueDTO;
import jakarta.persistence.EntityNotFoundException;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.springframework.stereotype.Service;

import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class CertificateService {

    private final UserRepository userRepository;
    private final CertificateRepository certificateRepository;
    private final KeystoreRepository keystoreRepository;
    private final CryptoService cryptoService;
    private final KeystoreService keystoreService;
    private final CertificateFactory certificateFactory;
    private final CSRRepository csrRepository;
    private final CSRService csrService;

    @Transactional
    public Certificate issueRootCertificate(UUID adminId, CertificateIssueDTO dto) throws Exception {
        User admin = userRepository.findById(adminId).orElseThrow(() -> new ResourceNotFoundException("Admin not found"));
        if (admin.getRole() != UserRole.ADMIN) {
            throw new SecurityException("Only admins can issue root certificates.");
        }

        String password = cryptoService.generateRandomPassword();
        Keystore keystore = new Keystore();
        keystore.setEncryptedPassword(cryptoService.encryptAES(password));
        keystoreRepository.save(keystore);

        KeyPair keyPair = cryptoService.generateRSAKeyPair();
        X500Name subjectAndIssuer = buildX500NameFromDto(dto);
        BigInteger serialNumber = new BigInteger(128, new SecureRandom());

        X509Certificate cert = certificateFactory.createCertificate(
                subjectAndIssuer, subjectAndIssuer,
                keyPair.getPublic(), keyPair.getPrivate(),
                dto.getValidFrom(), dto.getValidTo(),
                serialNumber, true,  dto
        );

        String alias = serialNumber.toString();
        var ks = keystoreService.loadKeyStore(keystore.getId(), password.toCharArray());
        ks.setKeyEntry(alias, keyPair.getPrivate(), password.toCharArray(), new java.security.cert.Certificate[]{cert});
        keystoreService.saveKeyStore(ks, keystore.getId(), password.toCharArray());

        return saveCertificateEntity(cert, admin, keystore, CertificateType.ROOT, serialNumber.toString());
    }

    @Transactional
    public Object issueCertificate(CertificateIssueDTO dto) throws Exception {
        // 1. Validacija i učitavanje izdavaoca
        Certificate issuerCertData = validateIssuer(dto.getIssuerSerialNumber());
        User subjectUser = userRepository.findById(dto.getSubjectUserId())
                .orElseThrow(() -> new ResourceNotFoundException("Subject user not found with ID: " + dto.getSubjectUserId()));

        Keystore keystore = issuerCertData.getKeystore();
        String password = cryptoService.decryptAES(keystore.getEncryptedPassword());

        PrivateKey issuerPrivateKey = keystoreService.getPrivateKey(
                keystore.getId(),
                password.toCharArray(),
                issuerCertData.getAlias()
        );
        java.security.cert.Certificate[] issuerChain = keystoreService.getCertificateChain(
                keystore.getId(),
                password.toCharArray(),
                issuerCertData.getAlias()
        );
        X509Certificate issuerCertX509 = (X509Certificate) issuerChain[0];

        // 2. Generisanje podataka za novi sertifikat
        KeyPair subjectKeyPair = cryptoService.generateRSAKeyPair();
        X500Name subjectName = buildX500NameFromDto(dto);
        //X500Name issuerName = new X500Name(issuerCertX509.getSubjectX500Principal().getName());
        X500Name issuerName = X500Name.getInstance(issuerCertX509.getSubjectX500Principal().getEncoded());
        BigInteger serialNumber = new BigInteger(128, new SecureRandom());

        boolean isCa = subjectUser.getRole() == UserRole.ADMIN || subjectUser.getRole() == UserRole.CA_USER;
        int keyUsage = isCa ?
                (KeyUsage.keyCertSign | KeyUsage.cRLSign) :
                (KeyUsage.digitalSignature | KeyUsage.keyEncipherment);

        // 3. Kreiranje sertifikata
        X509Certificate newCert = certificateFactory.createCertificate(
                subjectName,
                issuerName,
                subjectKeyPair.getPublic(),
                issuerPrivateKey,
                dto.getValidFrom(),
                dto.getValidTo(),
                serialNumber,
                isCa,
                dto
        );

        // 4. Čuvanje u keystore
        String alias = serialNumber.toString();
        KeyStore ks = keystoreService.loadKeyStore(keystore.getId(), password.toCharArray());

        if (isCa) {
            // SLUČAJ A: CA sertifikat (Intermediate)
            java.security.cert.Certificate[] newChain = new java.security.cert.Certificate[issuerChain.length + 1];
            newChain[0] = newCert;
            System.arraycopy(issuerChain, 0, newChain, 1, issuerChain.length);


            /*try {
                // 1. Provera potpisa novog sertifikata sa javnim ključem izdavaoca
                newCert.verify(issuerCertX509.getPublicKey());

                // 2. Provera validnosti novog sertifikata u odnosu na vreme
                newCert.checkValidity();

                // Ako oba prođu, problem je negde u KeyStore API-ju ili u strukturi samog issuerChain
                System.out.println("Potpis i validnost su OK.");
            } catch (Exception ex) {
                // Ovo će vam reći da li je problem u potpisu ili nečemu sličnom.
                System.err.println("Verifikacija lanca neuspešna: " + ex.getMessage());
                throw ex;
            }*/




            ks.setKeyEntry(alias, subjectKeyPair.getPrivate(), password.toCharArray(), newChain);
            System.out.println("Saving CA certificate with private key. Alias: " + alias);

            keystoreService.saveKeyStore(ks, keystore.getId(), password.toCharArray());
            Certificate certEntity = saveCertificateEntity(newCert, subjectUser, keystore, CertificateType.INTERMEDIATE, issuerCertData.getSerialNumber());

            // Vraćamo samo entitet (bez privatnog ključa)
            return new CertificateDetailsDTO(certEntity);

        } /*else {
            // SLUČAJ B: End-Entity sertifikat
            ks.setCertificateEntry(alias, newCert);
            System.out.println("Saving End-Entity certificate WITHOUT private key. Alias: " + alias);

            keystoreService.saveKeyStore(ks, keystore.getId(), password.toCharArray());
            Certificate certEntity = saveCertificateEntity(newCert, subjectUser, keystore, CertificateType.END_ENTITY, issuerCertData.getSerialNumber());

            // Pretvaranje privatnog ključa u PEM format (radi lakšeg preuzimanja)
            String privateKeyPem = cryptoService.privateKeyToPem(subjectKeyPair.getPrivate());

            // Vraćamo i sertifikat i privatni ključ
            return new CertificateWithPrivateKeyDTO(new CertificateDetailsDTO(certEntity), privateKeyPem);
        }*/
        return null; //TODO: END ENTITY CUVANJE??

    }

    /*@Transactional
    public Object issueCertificate(CertificateIssueDTO dto) throws Exception {

        // =================================================================
        // =========== 1. Validacija i učitavanje izdavaoca ================
        // =================================================================
        Certificate issuerCertData = validateIssuer(dto.getIssuerSerialNumber());
        User subjectUser = userRepository.findById(dto.getSubjectUserId())
                .orElseThrow(() -> new ResourceNotFoundException("Subject user not found with ID: " + dto.getSubjectUserId()));

        Keystore keystore = issuerCertData.getKeystore();
        String password = cryptoService.decryptAES(keystore.getEncryptedPassword());

        PrivateKey issuerPrivateKey = keystoreService.getPrivateKey(
                keystore.getId(),
                password.toCharArray(),
                issuerCertData.getAlias()
        );
        java.security.cert.Certificate[] issuerChain = keystoreService.getCertificateChain(
                keystore.getId(),
                password.toCharArray(),
                issuerCertData.getAlias()
        );
        X509Certificate issuerCertX509 = (X509Certificate) issuerChain[0];

        // LOGOVANJE #1: Provera Issuer Lanca (Očekujemo dužinu 1 jer je Root)
        System.out.println("--- LOG [1]: Issuer Provera ---");
        System.out.println("Issuer Cert Alias: " + issuerCertData.getAlias());
        System.out.println("Issuer Chain Length: " + issuerChain.length);

        // *** DODATNI LOG: Ispis detalja lanca dobijenog od Root-a ***
        for (int i = 0; i < issuerChain.length; i++) {
            X509Certificate certInChain = (X509Certificate) issuerChain[i];
            System.out.println("  -> Lanac[" + i + "] Subject: " + certInChain.getSubjectX500Principal().getName());
            System.out.println("  -> Lanac[" + i + "] Issuer:  " + certInChain.getIssuerX500Principal().getName());
        }
        // ***************************************************************

        System.out.println("Issuer Cert Not After: " + issuerCertX509.getNotAfter());
        // Provera ključnih osobina Izdavaoca
        try {
            boolean[] keyUsage = issuerCertX509.getKeyUsage();
            System.out.println("Issuer Basic Constraints (CA flag): " + (issuerCertX509.getBasicConstraints() > -1));
            System.out.println("Issuer KeyUsage[keyCertSign]: " + (keyUsage != null && keyUsage.length > 5 && keyUsage[5]));
        } catch (Exception e) {
            System.err.println("Greska pri citanju Issuer sertifikata (KeyUsage/Constraints): " + e.getMessage());
        }
        System.out.println("-------------------------------------");


        // =================================================================
        // =========== 2 & 3. Generisanje podataka i kreiranje sertifikata =
        // =================================================================
        KeyPair subjectKeyPair = cryptoService.generateRSAKeyPair();
        X500Name subjectName = buildX500NameFromDto(dto);
        X500Name issuerName = new X500Name(issuerCertX509.getSubjectX500Principal().getName());
        BigInteger serialNumber = new BigInteger(128, new SecureRandom());

        boolean isCa = subjectUser.getRole() == UserRole.ADMIN || subjectUser.getRole() == UserRole.CA_USER;
        int keyUsage = isCa ?
                (KeyUsage.keyCertSign | KeyUsage.cRLSign) :
                (KeyUsage.digitalSignature | KeyUsage.keyEncipherment);

        X509Certificate newCert = certificateFactory.createCertificate(
                subjectName,
                issuerName,
                subjectKeyPair.getPublic(),
                issuerPrivateKey,
                dto.getValidFrom(),
                dto.getValidTo(),
                serialNumber,
                isCa,
                keyUsage
        );

        // =================================================================
        // =========== 4. Čuvanje u keystore (Kritičan deo) ================
        // =================================================================
        String alias = serialNumber.toString();
        KeyStore ks = keystoreService.loadKeyStore(keystore.getId(), password.toCharArray());

        if (isCa) {
            // SLUČAJ A: CA sertifikat (Intermediate)

            // LOGOVANJE #2: Test Potpisa i Validnosti (potvrđuje da je kriptografija OK)
            try {
                newCert.verify(issuerCertX509.getPublicKey());
                newCert.checkValidity();
                System.out.println("LOG [2]: Potpis i validnost su OK.");
            } catch (Exception ex) {
                System.err.println("LOG [2] GRESKA: Verifikacija lanca neuspešna: " + ex.getMessage());
                throw ex;
            }

            // -----------------------------------------------------------------------------------
            // REŠENJE: KeyStore-u se predaje lanac koji sadrži SAMO novi sertifikat.
            // KeyStore će kasnije sam rekonstruisati puni lanac sa Root-om.
            // -----------------------------------------------------------------------------------
            java.security.cert.Certificate[] newChain = new java.security.cert.Certificate[1];
            newChain[0] = newCert; // Samo novi Intermediate CA
            // -----------------------------------------------------------------------------------

            System.out.println("LOG [3]: New Chain Length (za KeyStore): " + newChain.length);
            System.out.println("LOG [3]: New Cert Subject: " + newCert.getSubjectX500Principal().getName());

            // Pokušaj čuvanja. Ako ovo puca, greška je u KeyStore validaciji lanca.
            ks.setKeyEntry(alias, subjectKeyPair.getPrivate(), password.toCharArray(), newChain);
            System.out.println("LOG [4]: Saving Intermediate CA certificate with private key. Alias: " + alias + " - Uspesno.");

            keystoreService.saveKeyStore(ks, keystore.getId(), password.toCharArray());
            Certificate certEntity = saveCertificateEntity(newCert, subjectUser, keystore, CertificateType.INTERMEDIATE, issuerCertData.getSerialNumber());

            // Vraćamo samo entitet (bez privatnog ključa)
            return certEntity;

        } else {
            // SLUČAJ B: End-Entity sertifikat
            // Nema potrebe za lancem za setCertificateEntry, jer se ključ ne čuva
            ks.setCertificateEntry(alias, newCert);
            System.out.println("LOG [4]: Saving End-Entity certificate WITHOUT private key. Alias: " + alias + " - Uspesno.");

            keystoreService.saveKeyStore(ks, keystore.getId(), password.toCharArray());
            Certificate certEntity = saveCertificateEntity(newCert, subjectUser, keystore, CertificateType.END_ENTITY, issuerCertData.getSerialNumber());

            // Pretvaranje privatnog ključa u PEM format (radi lakšeg preuzimanja)
            String privateKeyPem = cryptoService.privateKeyToPem(subjectKeyPair.getPrivate());

            // Vraćamo i sertifikat i privatni ključ
            return new CertificateWithPrivateKeyDTO(new CertificateDetailsDTO(certEntity), privateKeyPem);
        }
    }*/

    /*@Transactional
    public Object issueCertificate(CertificateIssueDTO dto) throws Exception {
        // 1. Validacija i učitavanje izdavaoca
        Certificate issuerCertData = validateIssuer(dto.getIssuerSerialNumber());
        User subjectUser = userRepository.findById(dto.getSubjectUserId())
                .orElseThrow(() -> new ResourceNotFoundException("Subject user not found with ID: " + dto.getSubjectUserId()));

        Keystore keystore = issuerCertData.getKeystore();
        String password = cryptoService.decryptAES(keystore.getEncryptedPassword());

        PrivateKey issuerPrivateKey = keystoreService.getPrivateKey(
                keystore.getId(),
                password.toCharArray(),
                issuerCertData.getAlias()
        );
        java.security.cert.Certificate[] issuerChain = keystoreService.getCertificateChain(
                keystore.getId(),
                password.toCharArray(),
                issuerCertData.getAlias()
        );
        X509Certificate issuerCertX509 = (X509Certificate) issuerChain[0];

        // ... (deo koda za generisanje podataka i kreiranje novog sertifikata ostaje isti)
        // 2. Generisanje podataka za novi sertifikat
        KeyPair subjectKeyPair = cryptoService.generateRSAKeyPair();
        X500Name subjectName = buildX500NameFromDto(dto);
        //X500Name issuerName = new X500Name(issuerCertX509.getSubjectX500Principal().getName());
        X500Name issuerName = X500Name.getInstance(issuerCertX509.getSubjectX500Principal().getEncoded());
        BigInteger serialNumber = new BigInteger(128, new SecureRandom());

        boolean isCa = subjectUser.getRole() == UserRole.ADMIN || subjectUser.getRole() == UserRole.CA_USER;
        int keyUsage = isCa ?
                (KeyUsage.keyCertSign | KeyUsage.cRLSign) :
                (KeyUsage.digitalSignature | KeyUsage.keyEncipherment);

        // 3. Kreiranje sertifikata
        X509Certificate newCert = certificateFactory.createCertificate(
                subjectName,
                issuerName,
                subjectKeyPair.getPublic(),
                issuerPrivateKey,
                dto.getValidFrom(),
                dto.getValidTo(),
                serialNumber,
                isCa,
                keyUsage
        );


        // 4. Čuvanje u keystore
        String alias = serialNumber.toString();
        KeyStore ks = keystoreService.loadKeyStore(keystore.getId(), password.toCharArray());

        if (isCa) {
            // SLUČAJ A: CA sertifikat (Intermediate)
            java.security.cert.Certificate[] newChain = new java.security.cert.Certificate[issuerChain.length + 1];
            newChain[0] = newCert;
            System.arraycopy(issuerChain, 0, newChain, 1, issuerChain.length);

            // Testiranje potpisa i validnosti
            try {
                newCert.verify(issuerCertX509.getPublicKey());
                newCert.checkValidity();
                System.out.println("Potpis i validnost su OK.");
            } catch (Exception ex) {
                System.err.println("Verifikacija lanca neuspešna: " + ex.getMessage());
                throw ex;
            }

            // ==================================================================================
            // =========== DETALJNO LOGOVANJE LANCA PRE ČUVANJA (KEY LOGGING BLOCK) =============
            // ==================================================================================
            System.out.println("\n--- LOG: Analiza lanca ('newChain') pre poziva setKeyEntry ---");
            System.out.println("Ukupna dužina lanca za čuvanje: " + newChain.length);

            for (int i = 0; i < newChain.length; i++) {
                X509Certificate certInChain = (X509Certificate) newChain[i];
                System.out.println("-------------------------------------");
                System.out.println("Sertifikat na poziciji [" + i + "]:");
                System.out.println("  -> Subject: " + certInChain.getSubjectX500Principal().getName());
                System.out.println("  -> Issuer:  " + certInChain.getIssuerX500Principal().getName());
                System.out.println("  -> Serial#: " + certInChain.getSerialNumber());
                System.out.println("  -> Važi od: " + certInChain.getNotBefore());
                System.out.println("  -> Važi do: " + certInChain.getNotAfter());
                System.out.println("  -> Self-Signed: " + certInChain.getSubjectX500Principal().equals(certInChain.getIssuerX500Principal()));
                try {
                    System.out.println("  -> Basic Constraints (isCA): " + (certInChain.getBasicConstraints() > -1));
                    boolean[] keyUsageBits = certInChain.getKeyUsage();
                    System.out.println("  -> KeyUsage (keyCertSign): " + (keyUsageBits != null && keyUsageBits.length > 5 && keyUsageBits[5]));
                } catch (Exception e) {
                    System.err.println("    Greska pri citanju ekstenzija za sertifikat na poziciji [" + i + "]");
                }

                // Provera povezanosti sa prethodnim sertifikatom u lancu
                if (i > 0) {
                    X509Certificate previousCert = (X509Certificate) newChain[i - 1];
                    boolean isChainValid = previousCert.getIssuerX500Principal().equals(certInChain.getSubjectX500Principal());
                    System.out.println("  -> POVEZANOST: Issuer prethodnog sertifikata [" + (i - 1) + "] odgovara Subject-u ovog sertifikata [" + i + "]? -> " + isChainValid);
                    if (!isChainValid) {
                        System.out.println("     !!!! UPOZORENJE: LANAC JE PREKINUT NA OVOM MESTU !!!!");
                    }
                }
            }
            System.out.println("-------------------------------------");
            System.out.println("--- KRAJ ANALIZE LANCA --- \n");
            // ==================================================================================

            // Ovde će puknuti ako nešto u gore ispisanom lancu nije po volji KeyStore-a
            ks.setKeyEntry(alias, subjectKeyPair.getPrivate(), password.toCharArray(), newChain);
            System.out.println("Saving CA certificate with private key. Alias: " + alias);

            keystoreService.saveKeyStore(ks, keystore.getId(), password.toCharArray());
            Certificate certEntity = saveCertificateEntity(newCert, subjectUser, keystore, CertificateType.INTERMEDIATE, issuerCertData.getSerialNumber());

            // Vraćamo samo entitet (bez privatnog ključa)
            return certEntity;

        } else {
            // SLUČAJ B: End-Entity sertifikat
            ks.setCertificateEntry(alias, newCert);
            System.out.println("Saving End-Entity certificate WITHOUT private key. Alias: " + alias);

            keystoreService.saveKeyStore(ks, keystore.getId(), password.toCharArray());
            Certificate certEntity = saveCertificateEntity(newCert, subjectUser, keystore, CertificateType.END_ENTITY, issuerCertData.getSerialNumber());

            String privateKeyPem = cryptoService.privateKeyToPem(subjectKeyPair.getPrivate());
            return new CertificateWithPrivateKeyDTO(new CertificateDetailsDTO(certEntity), privateKeyPem);
        }
    }*/


    private Certificate validateIssuer(String issuerSerial) {
        Certificate issuer = certificateRepository.findBySerialNumber(issuerSerial)
                .orElseThrow(() -> new ResourceNotFoundException("Issuer certificate not found."));

        if (issuer.isRevoked()) {
            throw new CertificateValidationException("Issuer certificate is revoked.");
        }
        if (issuer.getValidTo().isBefore(LocalDateTime.now())) {
            throw new CertificateValidationException("Issuer certificate has expired.");
        }
        if (issuer.getType() == CertificateType.END_ENTITY) {
            throw new CertificateValidationException("End-entity certificates cannot issue new certificates.");
        }
        return issuer;
    }

    private Certificate saveCertificateEntity(X509Certificate cert, User owner, Keystore keystore, CertificateType type, String issuerSerial) {
        Certificate certEntity = new Certificate();
        certEntity.setSerialNumber(cert.getSerialNumber().toString());
        certEntity.setAlias(cert.getSerialNumber().toString());
        certEntity.setSubjectDN(cert.getSubjectX500Principal().getName());
        certEntity.setValidFrom(cert.getNotBefore().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime());
        certEntity.setValidTo(cert.getNotAfter().toInstant().atZone(ZoneId.systemDefault()).toLocalDateTime());
        certEntity.setType(type);
        certEntity.setOwner(owner);
        certEntity.setKeystore(keystore);
        certEntity.setIssuerSerialNumber(issuerSerial);
        return certificateRepository.save(certEntity);
    }

    private X500Name buildX500NameFromDto(CertificateIssueDTO dto) {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.CN, dto.getCommonName());
        builder.addRDN(BCStyle.O, dto.getOrganization());
        builder.addRDN(BCStyle.OU, dto.getOrganizationalUnit());
        builder.addRDN(BCStyle.C, dto.getCountry());
        builder.addRDN(BCStyle.EmailAddress, dto.getEmail());
        return builder.build();
    }

    public java.security.cert.Certificate[] loadCertificateChainById(Long certificateId) {
        try {
            Certificate certificate = certificateRepository.findById(certificateId)
                    .orElseThrow(() -> new EntityNotFoundException("Certificate not found", null));

            Keystore keystore = keystoreRepository.findById(certificate.getKeystore().getId())
                    .orElseThrow(() -> new EntityNotFoundException("Keystore not found", null));

            KeyStore ks = KeyStore.getInstance("PKCS12");

            String decryptedPassword = cryptoService.decryptAES(keystore.getEncryptedPassword());

            try (FileInputStream fis = new FileInputStream("data/keystores/keystore_" + keystore.getId() + ".p12")) {
                ks.load(fis, decryptedPassword.toCharArray());
            }

            System.out.println("=== Certificate Chain Debug ===");
            System.out.println("Certificate ID: " + certificateId);
            System.out.println("Certificate Alias: " + certificate.getAlias());
            System.out.println("Keystore ID: " + keystore.getId());

            // Get the complete certificate chain
            java.security.cert.Certificate[] chain = ks.getCertificateChain(certificate.getAlias());

            System.out.println("Raw chain length: " + (chain != null ? chain.length : "null"));

            if (chain != null) {
                for (int i = 0; i < chain.length; i++) {
                    if (chain[i] instanceof X509Certificate) {
                        X509Certificate x509Cert = (X509Certificate) chain[i];
                        System.out.println("Chain[" + i + "] Subject: " + x509Cert.getSubjectX500Principal().getName());
                        System.out.println("Chain[" + i + "] Issuer: " + x509Cert.getIssuerX500Principal().getName());
                        System.out.println("Chain[" + i + "] Serial: " + x509Cert.getSerialNumber());
                    }
                }
            }

            if (chain == null || chain.length == 0) {
                System.out.println("No certificate chain found, trying to get single certificate");
                // If no chain exists, return just the certificate itself
                X509Certificate cert = (X509Certificate) ks.getCertificate(certificate.getAlias());
                if (cert != null) {
                    System.out.println("Found single certificate: " + cert.getSubjectX500Principal().getName());

                    // Debug: Check for SANs in the certificate
                    try {
                        Collection<List<?>> sans = cert.getSubjectAlternativeNames();
                        if (sans != null && !sans.isEmpty()) {
                            System.out.println("=== SANs Found in Certificate ===");
                            for (List<?> san : sans) {
                                System.out.println("SAN Type: " + san.get(0) + ", Value: " + san.get(1));
                            }
                            System.out.println("=== End SANs Debug ===");
                        } else {
                            System.out.println("No SANs found in certificate");
                        }
                    } catch (Exception e) {
                        System.out.println("Error reading SANs: " + e.getMessage());
                    }

                    return new java.security.cert.Certificate[]{cert};
                }
                throw new EntityNotFoundException("Certificate not found in keystore", null);
            }

            System.out.println("=== End Certificate Chain Debug ===");
            return chain;
        } catch (Exception e) {
            System.err.println("Failed to load certificate chain: " + e.getMessage());
            e.printStackTrace();
            throw new EntityNotFoundException("Failed to load certificate chain from keystore", e);
        }
    }


    public byte[] convertCertificateChainToPKCS7(java.security.cert.Certificate[] chain) throws Exception {
        System.out.println("=== PKCS#7 Conversion Debug ===");
        System.out.println("Converting chain of " + chain.length + " certificates to PKCS#7");

        try {
            // Create a PKCS#7 container
            org.bouncycastle.cms.CMSProcessableByteArray content = new org.bouncycastle.cms.CMSProcessableByteArray(new byte[0]);
            org.bouncycastle.cms.CMSSignedDataGenerator gen = new org.bouncycastle.cms.CMSSignedDataGenerator();

            // Add all certificates to the container
            for (int i = 0; i < chain.length; i++) {
                if (chain[i] instanceof X509Certificate) {
                    X509Certificate x509Cert = (X509Certificate) chain[i];
                    System.out.println("Adding certificate " + i + " to PKCS#7: " + x509Cert.getSubjectX500Principal().getName());
                    gen.addCertificate(new org.bouncycastle.cert.X509CertificateHolder(x509Cert.getEncoded()));
                }
            }

            // Generate the PKCS#7 data
            org.bouncycastle.cms.CMSSignedData signedData = gen.generate(content, false);
            byte[] pkcs7Bytes = signedData.getEncoded();

            System.out.println("PKCS#7 conversion complete, size: " + pkcs7Bytes.length + " bytes");
            System.out.println("=== End PKCS#7 Conversion Debug ===");

            return pkcs7Bytes;
        } catch (Exception e) {
            System.err.println("Failed to convert to PKCS#7: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }


    @Transactional
    public CertificateDetailsDTO issueCertificateFromCsr(Long csrId, String issuerSerialNumber, ZonedDateTime validFrom, ZonedDateTime validTo) throws Exception {
        // 1. Učitavanje podataka
        CSR csr = csrRepository.findById(csrId)
                .orElseThrow(() -> new ResourceNotFoundException("CSR not found with ID: " + csrId));

        Certificate issuerCertData = validateIssuer(issuerSerialNumber);
        Keystore keystore = issuerCertData.getKeystore();
        String password = cryptoService.decryptAES(keystore.getEncryptedPassword());
        PrivateKey issuerPrivateKey = keystoreService.getPrivateKey(keystore.getId(), password.toCharArray(), issuerCertData.getAlias());
        java.security.cert.Certificate[] issuerChain = keystoreService.getCertificateChain(keystore.getId(), password.toCharArray(), issuerCertData.getAlias());
        X509Certificate issuerCertX509 = (X509Certificate) issuerChain[0];

        // 2. Parsiranje i validacija CSR-a
        PKCS10CertificationRequest parsedCsr = csrService.parseCsr(csr.getPemContent());
        csrService.validateCsr(parsedCsr); // Validacija potpisa i ključa

        // 3. Provera validnosti datuma
        if (validFrom.isBefore(issuerCertX509.getNotBefore().toInstant().atZone(ZoneId.systemDefault()).toOffsetDateTime().toZonedDateTime()) ||
                validTo.isAfter(issuerCertX509.getNotAfter().toInstant().atZone(ZoneId.systemDefault()).toOffsetDateTime().toZonedDateTime())) {
            throw new CertificateValidationException("Requested validity period is outside the issuer's validity period.");
        }

        // 4. Ekstrakcija podataka iz CSR-a
        JcaPKCS10CertificationRequest jcaCsr = new JcaPKCS10CertificationRequest(parsedCsr);
        PublicKey subjectPublicKey = jcaCsr.getPublicKey();
        X500Name subjectName = parsedCsr.getSubject();
        X500Name issuerName = X500Name.getInstance(issuerCertX509.getSubjectX500Principal().getEncoded());

        // 5. Hardkodovanje ekstenzija (primer)
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        Extensions extensions = new Extensions(new Extension[] {
                // Subject Alternative Name (SAN) - primer sa DNS i IP adresom
                new Extension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName[] {
                        new GeneralName(GeneralName.dNSName, "example.com"),
                        new GeneralName(GeneralName.iPAddress, "192.168.1.1")
                }).getEncoded()),
                // Authority Key Identifier (AKI)
                new Extension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(issuerCertX509).getEncoded()),
                // Subject Key Identifier (SKI)
                new Extension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(subjectPublicKey).getEncoded())
        });

        // 6. Kreiranje sertifikata
        X509Certificate newCert = certificateFactory.createCertificate2(
                subjectName,
                issuerName,
                subjectPublicKey, // Javni ključ iz CSR-a
                issuerPrivateKey, // Privatni ključ izdavaoca
                validFrom,
                validTo,
                new BigInteger(128, new SecureRandom()), // Novi serijski broj
                false, // End-Entity sertifikat NIJE CA
                KeyUsage.digitalSignature | KeyUsage.keyEncipherment, // Tipičan KeyUsage za EE
                extensions // Prosleđujemo hardkodovane ekstenzije
        );

        // 7. Čuvanje u keystore - KAO TRUSTED CERTIFICATE (BEZ PRIVATNOG KLJUČA)
        String alias = newCert.getSerialNumber().toString();
        KeyStore ks = keystoreService.loadKeyStore(keystore.getId(), password.toCharArray());

        // Koristimo setCertificateEntry jer NE čuvamo privatni ključ subjekta
        ks.setCertificateEntry(alias, newCert);

        // Ipak, da bi lanac bio kompletan, moramo dodati i lanac izdavaoca kao trusted entry
        for (int i = 0; i < issuerChain.length; i++) {
            X509Certificate certInChain = (X509Certificate) issuerChain[i];
            ks.setCertificateEntry(certInChain.getSerialNumber().toString(), certInChain);
        }

        keystoreService.saveKeyStore(ks, keystore.getId(), password.toCharArray());

        // 8. Čuvanje u bazu i ažuriranje statusa CSR-a
        Certificate certEntity = saveCertificateEntity(newCert, csr.getOwner(), keystore, CertificateType.END_ENTITY, issuerCertData.getSerialNumber());

        csr.setStatus(CSR.CsrStatus.APPROVED);
        csrRepository.save(csr);

        return new CertificateDetailsDTO(certEntity);
    }

    // Takođe, ne zaboravite da popunite else blok u originalnoj issueCertificate metodi
    // ako i dalje želite da je koristite za EE sertifikate gde vi generišete ključeve.
}


