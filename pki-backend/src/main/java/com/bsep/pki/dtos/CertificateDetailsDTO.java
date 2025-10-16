package com.bsep.pki.dtos;

import com.bsep.pki.models.Certificate;
import lombok.Data;
import java.time.LocalDateTime;

@Data
public class CertificateDetailsDTO {
    private Long id;
    private String serialNumber;
    private String subjectDN;
    private String issuerSerialNumber;
    private LocalDateTime validFrom;
    private LocalDateTime validTo;
    private String type;
    private boolean isRevoked;

    public CertificateDetailsDTO(Certificate cert) {
        this.id = cert.getId();
        this.serialNumber = cert.getSerialNumber();
        this.subjectDN = cert.getSubjectDN();
        this.issuerSerialNumber = cert.getIssuerSerialNumber();
        this.validFrom = cert.getValidFrom();
        this.validTo = cert.getValidTo();
        this.type = cert.getType().name();
        this.isRevoked = cert.isRevoked();
    }
}