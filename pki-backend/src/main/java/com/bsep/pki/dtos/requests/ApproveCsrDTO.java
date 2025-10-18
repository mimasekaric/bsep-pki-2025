package com.bsep.pki.dtos.requests;

import lombok.Data;

import java.time.ZonedDateTime;

@Data
public class ApproveCsrDTO {
    private String issuerSerialNumber;
    private ZonedDateTime validFrom;
    private ZonedDateTime validTo;
}
