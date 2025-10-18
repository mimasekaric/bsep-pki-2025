package com.bsep.pki.services;

import com.bsep.pki.dtos.CertificateIssueDTO;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Component
public class CertificateFactory {

    @Value("${crl.base.url}")
    private String crlBaseUrl;
    /*public X509Certificate createCertificate(
            X500Name subject, X500Name issuer,
            PublicKey subjectPublicKey, PrivateKey issuerPrivateKey,
            ZonedDateTime validFrom, ZonedDateTime validTo,
            BigInteger serialNumber,
            boolean isCa, int keyUsage) throws Exception {

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, serialNumber,
                Date.from(validFrom.toInstant()),
                Date.from(validTo.toInstant()),
                subject, subjectPublicKey);

        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsage));

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .setProvider("BC").build(issuerPrivateKey);

        return new JcaX509CertificateConverter().setProvider("BC")
                .getCertificate(certBuilder.build(contentSigner));
    }*/

    public X509Certificate createCertificate(
            X500Name subject, X500Name issuer,
            PublicKey subjectPublicKey, PrivateKey issuerPrivateKey,
            ZonedDateTime validFrom, ZonedDateTime validTo,
            BigInteger serialNumber, boolean isCa,
            CertificateIssueDTO extensionsDto // Prosleđujemo ceo DTO radi ekstenzija
    ) throws Exception {

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, serialNumber,
                Date.from(validFrom.toInstant()), Date.from(validTo.toInstant()),
                subject, subjectPublicKey);

        // Dodavanje ekstenzija
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));

        addKeyUsage(certBuilder, extensionsDto.getKeyUsages(), isCa);
        addExtendedKeyUsage(certBuilder, extensionsDto.getExtendedKeyUsages());
        addSubjectAlternativeNames(certBuilder, extensionsDto.getSubjectAlternativeNames());

        // Dodajemo CRL link samo ako nije root sertifikat
        if (extensionsDto.getIssuerSerialNumber() != null) {
            addCrlDistributionPoint(certBuilder, extensionsDto.getIssuerSerialNumber());
        }

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(issuerPrivateKey);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(contentSigner));
    }

    private void addKeyUsage(X509v3CertificateBuilder certBuilder, List<String> usages, boolean isCa) throws CertIOException, CertIOException {
        if (usages == null || usages.isEmpty()) {
            // Default vrednosti
            int keyUsageBits = isCa ? (KeyUsage.keyCertSign | KeyUsage.cRLSign) : (KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
            certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsageBits));
            return;
        }

        int keyUsageBits = 0;
        for (String usage : usages) {
            switch (usage.toUpperCase()) {
                case "DIGITAL_SIGNATURE": keyUsageBits |= KeyUsage.digitalSignature; break;
                case "NON_REPUDIATION": keyUsageBits |= KeyUsage.nonRepudiation; break;
                case "KEY_ENCIPHERMENT": keyUsageBits |= KeyUsage.keyEncipherment; break;
                case "DATA_ENCIPHERMENT": keyUsageBits |= KeyUsage.dataEncipherment; break;
                case "KEY_AGREEMENT": keyUsageBits |= KeyUsage.keyAgreement; break;
                case "KEY_CERT_SIGN": keyUsageBits |= KeyUsage.keyCertSign; break;
                case "CRL_SIGN": keyUsageBits |= KeyUsage.cRLSign; break;
                case "ENCIPHER_ONLY": keyUsageBits |= KeyUsage.encipherOnly; break;
                case "DECIPHER_ONLY": keyUsageBits |= KeyUsage.decipherOnly; break;
            }
        }
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsageBits));
    }

    private void addExtendedKeyUsage(X509v3CertificateBuilder certBuilder, List<String> ekuTypes) throws CertIOException {
        if (ekuTypes == null || ekuTypes.isEmpty()) return;

        List<KeyPurposeId> purposes = new ArrayList<>();
        for (String type : ekuTypes) {
            switch (type.toUpperCase()) {
                case "SERVER_AUTH": purposes.add(KeyPurposeId.id_kp_serverAuth); break;
                case "CLIENT_AUTH": purposes.add(KeyPurposeId.id_kp_clientAuth); break;
                case "CODE_SIGNING": purposes.add(KeyPurposeId.id_kp_codeSigning); break;
                case "EMAIL_PROTECTION": purposes.add(KeyPurposeId.id_kp_emailProtection); break;
            }
        }
        if (!purposes.isEmpty()) {
            certBuilder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(purposes.toArray(new KeyPurposeId[0])));
        }
    }

    private void addSubjectAlternativeNames(X509v3CertificateBuilder certBuilder, List<String> sans) throws CertIOException {
        if (sans == null || sans.isEmpty()) return;

        List<GeneralName> generalNames = new ArrayList<>();
        for (String san : sans) {
            if (san.toLowerCase().startsWith("dns:")) {
                generalNames.add(new GeneralName(GeneralName.dNSName, san.substring(4)));
            } else if (san.toLowerCase().startsWith("ip:")) {
                generalNames.add(new GeneralName(GeneralName.iPAddress, san.substring(3)));
            } else if (san.toLowerCase().startsWith("email:")) {
                generalNames.add(new GeneralName(GeneralName.rfc822Name, san.substring(6)));
            }
        }
        if (!generalNames.isEmpty()) {
            certBuilder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(generalNames.toArray(new GeneralName[0])));
        }
    }

    private void addCrlDistributionPoint(X509v3CertificateBuilder certBuilder, String issuerSerial) throws CertIOException {
        String crlUrl = crlBaseUrl + "/" + issuerSerial;
        GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, crlUrl);
        DistributionPointName dpn = new DistributionPointName(new GeneralNames(gn));
        DistributionPoint distPoint = new DistributionPoint(dpn, null, null);
        certBuilder.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(new DistributionPoint[]{distPoint}));
    }

    public X509Certificate createCertificateFromCsrData(
            X500Name subject, X500Name issuer,
            PublicKey subjectPublicKey, PrivateKey issuerPrivateKey,
            ZonedDateTime validFrom, ZonedDateTime validTo,
            BigInteger serialNumber,
            X509Certificate issuerCert, // Izdavalac
            Extensions requestedExtensions // Ekstenzije pročitane iz CSR-a
    ) throws Exception {

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, serialNumber,
                Date.from(validFrom.toInstant()), Date.from(validTo.toInstant()),
                subject, subjectPublicKey);

        // === VALIDACIJA I KOPIRANJE EKSTENZIJA IZ CSR-a ===
        if (requestedExtensions != null) {
            ASN1ObjectIdentifier[] oids = requestedExtensions.getExtensionOIDs();
            for (ASN1ObjectIdentifier oid : oids) {
                Extension ext = requestedExtensions.getExtension(oid);

                // === SIGURNOSNA PROVERA: Odbaci ako korisnik traži CA prava ===
                if (oid.equals(Extension.basicConstraints)) {
                    BasicConstraints bc = BasicConstraints.getInstance(ext.getParsedValue());
                    if (bc.isCA()) {
                        throw new SecurityException("CSR validation failed: End-Entity cannot request to be a CA.");
                    }
                }
                if (oid.equals(Extension.keyUsage)) {
                    KeyUsage ku = KeyUsage.getInstance(ext.getParsedValue());
                    if (ku.hasUsages(KeyUsage.keyCertSign) || ku.hasUsages(KeyUsage.cRLSign)) {
                        throw new SecurityException("CSR validation failed: End-Entity cannot request keyCertSign or cRLSign.");
                    }
                }

                // Ako je provera prošla, kopiraj ekstenziju
                certBuilder.addExtension(ext);
            }
        } else {
            // Ako CSR nema ekstenzije, dodaj default za End-Entity
            certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        }

        // === DODAVANJE OBAVEZNIH EKSTENZIJA KOJE POSTAVLJA CA ===
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        certBuilder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(issuerCert));
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(subjectPublicKey));
        addCrlDistributionPoint(certBuilder, issuerCert.getSerialNumber().toString());

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(issuerPrivateKey);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(contentSigner));
    }




}

