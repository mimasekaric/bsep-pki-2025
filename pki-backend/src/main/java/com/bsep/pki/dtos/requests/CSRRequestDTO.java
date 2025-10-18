package com.bsep.pki.dtos.requests;


import lombok.Data;

import java.time.LocalDateTime;

@Data
public class CSRRequestDTO {
    private String pemContent;
    private String signingCertificateSerialNumber;
    private LocalDateTime requestedValidFrom;
    private LocalDateTime requestedValidTo;
}
