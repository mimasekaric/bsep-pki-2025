package com.bsep.pki.services;

import com.bsep.pki.dtos.CertificateIssueDTO;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Component;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.Date;

@Component
public class CertificateFactory {

    public X509Certificate createCertificate(
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
    }
    public X509Certificate createCertificate2(
            X500Name subject,
            X500Name issuer,
            PublicKey subjectPublicKey,
            PrivateKey issuerPrivateKey,
            ZonedDateTime validFrom,
            ZonedDateTime validTo,
            BigInteger serialNumber,
            boolean isCa,
            int keyUsage,
            Extensions extensions // <-- NOVI PARAMETAR
    ) throws Exception {

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, serialNumber,
                Date.from(validFrom.toInstant()),
                Date.from(validTo.toInstant()),
                subject, subjectPublicKey);

        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsage));

        // DODAVANJE HARDKODOVANIH EKSTENZIJA AKO SU PROSLEĐENE
        if (extensions != null) {
            ASN1ObjectIdentifier[] oids = extensions.getExtensionOIDs();
            for (ASN1ObjectIdentifier oid : oids) {
                certBuilder.addExtension(extensions.getExtension(oid));
            }
        }

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSAEncryption")
                .setProvider("BC").build(issuerPrivateKey);

        return new JcaX509CertificateConverter().setProvider("BC")
                .getCertificate(certBuilder.build(contentSigner));
    }
}

