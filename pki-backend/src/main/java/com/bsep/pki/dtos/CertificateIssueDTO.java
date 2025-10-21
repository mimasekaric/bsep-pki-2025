package com.bsep.pki.dtos;


import com.bsep.pki.enums.CertificateType;
import lombok.Data;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.UUID;

@Data
public class CertificateIssueDTO {
    private String commonName;
    private String organization;
    private String organizationalUnit;
    private String country;
    private String email;

    private ZonedDateTime validFrom;
    private ZonedDateTime validTo;

    private String issuerSerialNumber;
    private UUID subjectUserId;
    private CertificateType certificateType;

    private List<String> keyUsages;
    private List<String> extendedKeyUsages;
    private List<String> subjectAlternativeNames;
}
