package com.bsep.pki.services;


import com.bsep.pki.dtos.CertificateDetailsDTO;
import com.bsep.pki.dtos.CertificateWithPrivateKeyDTO;
import com.bsep.pki.dtos.IssuerDto;
import com.bsep.pki.dtos.requests.ApproveCsrDTO;
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
import com.bsep.pki.util.DnParserUtil;
import jakarta.persistence.EntityNotFoundException;
import jakarta.transaction.Transactional;
import jakarta.validation.ValidationException;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class CertificateService {

    private final UserRepository userRepository;
    private final CertificateRepository certificateRepository;
    private final KeystoreRepository keystoreRepository;
    private final CryptoService cryptoService;
    private final KeystoreService keystoreService;
    private final CertificateFactory certificateFactory;
    private final CrlService crlService;
    private final CSRRepository csrRepository;
    private final CSRService csrService;
    private final CertificateTemplateService templateService;

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
        if (dto.getTemplateId() != null) {
            System.out.println("Template ID provided: " + dto.getTemplateId() + ". Applying template logic.");
            CertificateTemplate template = templateService.getTemplateById(dto.getTemplateId());

            // 1. Provera da li se issuer iz DTO-a poklapa sa onim iz šablona
            if (!template.getIssuerSerialNumber().equals(dto.getIssuerSerialNumber())) {
                throw new ValidationException("Issuer specified in request does not match the template's issuer.");
            }

            // 2. Validacija na osnovu regularnih izraza i TTL-a iz šablona
            validateCertificateDataWithTemplate(dto, template);

            // 3. Popunjavanje ekstenzija ako ih korisnik nije poslao
            // Ako je korisnik poslao svoju listu, ta lista ima prednost.
            // Ako nije, koristimo podrazumevanu iz šablona.
            if (dto.getKeyUsages() == null || dto.getKeyUsages().isEmpty()) {
                dto.setKeyUsages(template.getKeyUsage());
                System.out.println("Applying Key Usages from template: " + template.getKeyUsage());
            }
            if (dto.getExtendedKeyUsages() == null || dto.getExtendedKeyUsages().isEmpty()) {
                dto.setExtendedKeyUsages(template.getExtendedKeyUsage());
                System.out.println("Applying Extended Key Usages from template: " + template.getExtendedKeyUsage());
            }
        }
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

        CertificateType typeToIssue = dto.getCertificateType();

        if (typeToIssue == null || typeToIssue == CertificateType.ROOT) {
            throw new ValidationException("Invalid or missing certificate type for issuance (must be INTERMEDIATE or END_ENTITY).");
        }

        // 2. Određujemo da li je novi sertifikat CA sertifikat
        boolean isCa = typeToIssue == CertificateType.INTERMEDIATE;

        /*
        int keyUsage = isCa ?
                (KeyUsage.keyCertSign | KeyUsage.cRLSign) :
                (KeyUsage.digitalSignature | KeyUsage.keyEncipherment);*/

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

        } else {


            java.security.cert.Certificate[] newChain = new java.security.cert.Certificate[issuerChain.length + 1];
            newChain[0] = newCert;
            System.arraycopy(issuerChain, 0, newChain, 1, issuerChain.length);


            ks.setKeyEntry(alias, subjectKeyPair.getPrivate(), password.toCharArray(), newChain);

            keystoreService.saveKeyStore(ks, keystore.getId(), password.toCharArray());

            Certificate certEntity = saveCertificateEntity(newCert, subjectUser, keystore, CertificateType.END_ENTITY, issuerCertData.getSerialNumber());


            String privateKeyPem = cryptoService.privateKeyToPem(subjectKeyPair.getPrivate());
            return new CertificateWithPrivateKeyDTO(new CertificateDetailsDTO(certEntity), privateKeyPem);
        }

    }

    private void validateCertificateDataWithTemplate(CertificateIssueDTO dto, CertificateTemplate template) {
        // Validacija Common Name
        if (template.getCommonNameRegex() != null && !template.getCommonNameRegex().isBlank()) {
            if (!dto.getCommonName().matches(template.getCommonNameRegex())) {
                throw new ValidationException("Common Name does not match the template's required pattern: " + template.getCommonNameRegex());
            }
        }

        // Validacija Subject Alternative Names (SANs)
        if (template.getSanRegex() != null && !template.getSanRegex().isBlank()) {
            if (dto.getSubjectAlternativeNames() != null) {
                for (String sanValue : dto.getSubjectAlternativeNames()) {
                    // Ekstrahujemo samo vrednost (npr. 'example.com' iz 'dns:example.com')
                    String actualValue = sanValue.contains(":") ? sanValue.substring(sanValue.indexOf(":") + 1) : sanValue;
                    if (!actualValue.matches(template.getSanRegex())) {
                        throw new ValidationException("A SAN value '" + actualValue + "' does not match the template's required pattern: " + template.getSanRegex());
                    }
                }
            }
        }

        // Validacija TTL (vreme važenja)
        long requestedTtlDays = Duration.between(dto.getValidFrom(), dto.getValidTo()).toDays();
        if (requestedTtlDays > template.getTtlDays()) {
            throw new ValidationException("The requested certificate duration (" + requestedTtlDays + " days) exceeds the maximum allowed by the template (" + template.getTtlDays() + " days).");
        }
    }

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
    public void revokeCertificate(String serialNumber, String reason, UUID requestingUserId) throws Exception {
        Certificate certToRevoke = certificateRepository.findBySerialNumber(serialNumber)
                .orElseThrow(() -> new ResourceNotFoundException("Certificate not found"));

        if (certToRevoke.isRevoked()) {
            throw new CertificateValidationException("Certificate is already revoked.");
        }

        User requestingUser = userRepository.findById(requestingUserId).orElseThrow(() -> new ResourceNotFoundException("User not found"));

        // Provera permisija (admin može sve, ostali samo svoje)
        if (requestingUser.getRole() != UserRole.ADMIN && !certToRevoke.getOwner().getId().equals(requestingUserId)) {
            throw new SecurityException("You do not have permission to revoke this certificate.");
        }

        // Pokreni proces povlačenja
        performRevocation(certToRevoke, reason);
    }

    private void performRevocation(Certificate certificate, String reason) throws Exception {
        if (certificate.isRevoked()) return;
        if (reason == null) reason = "unspecified"; // fallback
        certificate.setRevoked(true);
        certificate.setRevocationReason(reason);
        certificate.setRevocationDate(LocalDateTime.now());
        certificateRepository.save(certificate);


        if (certificate.getType() == CertificateType.ROOT || certificate.getType() == CertificateType.INTERMEDIATE) {
            List<Certificate> issuedCerts = certificateRepository.findByIssuerSerialNumber(certificate.getSerialNumber());
            for (Certificate cert : issuedCerts) {
                performRevocation(cert, "cACompromise"); // Standardni X.509 razlog
            }
        }

         crlService.regenerateCrl(certificate.getIssuerSerialNumber());
    }



    @Transactional
    public CertificateDetailsDTO issueCertificateFromCsr(
            Long csrId,
            ApproveCsrDTO dto
    ) throws Exception {

        // 1. Učitavanje podataka
        CSR csr = csrRepository.findById(csrId)
                .orElseThrow(() -> new ResourceNotFoundException("CSR not found with ID: " + csrId));

        // DTO sada sadrži serijski broj izdavaoca
        Certificate issuerCertData = validateIssuer(dto.getIssuerSerialNumber());
        Keystore keystore = issuerCertData.getKeystore();
        String password = cryptoService.decryptAES(keystore.getEncryptedPassword());
        PrivateKey issuerPrivateKey = keystoreService.getPrivateKey(keystore.getId(), password.toCharArray(), issuerCertData.getAlias());
        X509Certificate issuerCertX509 = (X509Certificate) keystoreService.getCertificateChain(
                keystore.getId(), password.toCharArray(), issuerCertData.getAlias()
        )[0];

        // 2. Parsiranje i validacija CSR-a
        PKCS10CertificationRequest parsedCsr = csrService.parseCsr(csr.getPemContent());
        csrService.validateCsr(parsedCsr);

        // 3. Provera validnosti datuma iz DTO
        /*if (dto.getValidFrom().isBefore(issuerCertX509.getNotBefore().toInstant().atZone(ZoneId.systemDefault()).toOffsetDateTime().toZonedDateTime()) ||
                dto.getValidTo().isAfter(issuerCertX509.getNotAfter().toInstant().atZone(ZoneId.systemDefault()).toOffsetDateTime().toZonedDateTime())) {
            throw new CertificateValidationException("Requested validity period is outside the issuer's validity period.");
        }*/

        // 4. Ekstrakcija ključnih podataka iz CSR-a
        JcaPKCS10CertificationRequest jcaCsr = new JcaPKCS10CertificationRequest(parsedCsr);
        PublicKey subjectPublicKey = jcaCsr.getPublicKey();
        X500Name subjectName = parsedCsr.getSubject(); // Subject ime se uzima iz CSR-a
        X500Name issuerName = X500Name.getInstance(issuerCertX509.getSubjectX500Principal().getEncoded());

        Extensions requestedExtensions = csrService.getExtensionsFromCsr(parsedCsr);

        // 4. Kreiranje sertifikata
        // Potrebna nam je nova metoda u fabrici
        X509Certificate newCert = certificateFactory.createCertificateFromCsrData(
                subjectName,
                issuerName,
                subjectPublicKey,
                issuerPrivateKey,
                dto.getValidFrom(), // Datumi i dalje dolaze iz DTO-a
                dto.getValidTo(),
                new BigInteger(128, new SecureRandom()),
                issuerCertX509,
                requestedExtensions // Prosleđujemo ekstenzije iz CSR-a
        );

        // 6. Čuvanje u keystore (BEZ PRIVATNOG KLJUČA)
        String alias = newCert.getSerialNumber().toString();
        KeyStore ks = keystoreService.loadKeyStore(keystore.getId(), password.toCharArray());

        ks.setCertificateEntry(alias, newCert);

        keystoreService.saveKeyStore(ks, keystore.getId(), password.toCharArray());

        Certificate certEntity = saveCertificateEntity(newCert, csr.getOwner(), keystore, CertificateType.END_ENTITY, issuerCertData.getSerialNumber());

        csr.setStatus(CSR.CsrStatus.APPROVED);
        csrRepository.save(csr);

        return new CertificateDetailsDTO(certEntity);
    }

    public List<IssuerDto> getPotentialIssuers() {
        try {
            Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            if (principal == null) {
                System.err.println("Greska: Principal je null. Korisnik nije autentifikovan.");
                return Collections.emptyList();
            }

            // ==========================================================
            // ==== KONAČNO ISPRAVNO REŠENJE ============================
            // ==========================================================
            String email;
            if (principal instanceof Jwt) {
                // Ako je Principal Jwt objekat, uzimamo 'subject' claim iz njega.
                Jwt jwt = (Jwt) principal;
                email = jwt.getSubject();
            } else {
                // Fallback za druge konfiguracije (iako se kod Vas neće desiti)
                throw new IllegalStateException("Principal nije očekivanog tipa (Jwt). Tip je: " + principal.getClass().getName());
            }
            // ==========================================================

            if (email == null || email.isBlank()) {
                throw new IllegalStateException("Email (subject) u JWT tokenu je prazan ili ne postoji.");
            }

            String cleanedEmail = email.trim();
            System.out.println("Pokušavam da pronađem korisnika sa emailom iz JWT-a: '" + cleanedEmail + "'");

            User user = userRepository.findByEmail(cleanedEmail)
                    .orElseThrow(() -> new IllegalStateException("Ulogovani korisnik sa emailom '" + cleanedEmail + "' nije pronađen u bazi."));


            if (user.getRole() == null || user.getRoleAsString() == null) {
                System.err.println("Korisnik " + user.getEmail() + " nema definisanu ulogu!");
                return Collections.emptyList();
            }

            List<CertificateType> caTypes = List.of(CertificateType.ROOT, CertificateType.INTERMEDIATE);
            LocalDateTime now = LocalDateTime.now();
            List<Certificate> issuerCertificates;
            String userRole = user.getRoleAsString();

            if ("ADMIN".equals(userRole)) {
                issuerCertificates = certificateRepository.findAllActiveCaCertificates(caTypes, now);
            } else if ("CA_USER".equals(userRole) || "ORDINARY_USER".equals(userRole)) {
                issuerCertificates = certificateRepository.findAllActiveCaCertificatesByOwner(user, caTypes, now);

            } else {
                issuerCertificates = Collections.emptyList();
            }

            return issuerCertificates.stream()
                    .filter(cert -> cert != null && cert.getSubjectDN() != null && cert.getValidFrom() != null && cert.getValidTo() != null)
                    .map(cert -> new IssuerDto(
                            cert.getSerialNumber(),
                            DnParserUtil.extractField(cert.getSubjectDN(), "CN"),
                            Date.from(cert.getValidFrom().atZone(ZoneId.systemDefault()).toInstant()),
                            Date.from(cert.getValidTo().atZone(ZoneId.systemDefault()).toInstant())
                    ))
                    .collect(Collectors.toList());

        } catch (Exception e) {
            e.printStackTrace();
            throw e;
        }
    }


}


