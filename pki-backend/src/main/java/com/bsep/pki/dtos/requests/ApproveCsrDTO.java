package com.bsep.pki.dtos.requests;

import lombok.Data;

import java.time.ZonedDateTime;

@Data
public class ApproveCsrDTO {
    private String signingCertificateSerialNumber;
}
