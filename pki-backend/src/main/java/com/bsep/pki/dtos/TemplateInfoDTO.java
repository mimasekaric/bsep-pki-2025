package com.bsep.pki.dtos;

import java.util.List;

public record TemplateInfoDTO(
        Long id,
        String templateName,
        String issuerSerialNumber,
        String commonNameRegex,
        String sanRegex,
        int ttlDays,
        List<String> keyUsage,
        List<String> extendedKeyUsage
) {}