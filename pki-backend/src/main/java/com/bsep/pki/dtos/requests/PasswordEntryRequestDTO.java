package com.bsep.pki.dtos.requests;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class PasswordEntryRequestDTO {
    @NotBlank
    private String siteName;
    @NotBlank
    private String username;
    @NotBlank
    private String encryptedPassword; // Ovo je već enkriptovana lozinka sa frontenda
}