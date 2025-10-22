package com.bsep.pki.dtos;

import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.util.UUID;

@Data
public class SharePasswordDTO {

    private UUID shareWithUserId;
    @NotNull
    private String shareWithUserName;
    @NotNull
    private String reEncryptedPassword; // Lozinka re-enkriptovana javnim ključem korisnika sa kojim se deli
}