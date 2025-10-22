package com.bsep.pki.dtos.requests;


import lombok.Data;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
public class CSRRequestDTO {
    private String pemContent;
    private UUID approverId;
    private LocalDateTime requestedValidFrom;
    private LocalDateTime requestedValidTo;
}
