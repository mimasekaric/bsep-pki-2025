package com.bsep.pki.dtos;


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

    private List<String> keyUsages; // Npr: "DIGITAL_SIGNATURE", "KEY_ENCIPHERMENT"
    private List<String> extendedKeyUsages; // Npr: "SERVER_AUTH", "CLIENT_AUTH"
    private List<String> subjectAlternativeNames; // Npr: "dns:example.com", "ip:192.168.1.1"
}
