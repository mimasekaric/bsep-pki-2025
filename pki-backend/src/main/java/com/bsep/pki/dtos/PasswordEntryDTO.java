package com.bsep.pki.dtos;

import com.bsep.pki.models.Password;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
@NoArgsConstructor
public class PasswordEntryDTO {
    private Long id;
    private UUID ownerId;
    private String ownerUsername;
    private String siteName;
    private String username;
    private LocalDateTime createdAt;
    // EncryptedPassword se NE vraća direktno. Za dekripciju se koristi poseban endpoint/proces.
    // Dodatno, ne vraćamo ni sharedWith mapu direktno u ovom DTO-u radi jednostavnosti.

    public PasswordEntryDTO(Password entry) {
        this.id = entry.getId();
        this.ownerId = entry.getOwner().getId();
        this.ownerUsername = entry.getOwnerUsername();
        this.siteName = entry.getSiteName();
        this.username = entry.getUsername();
        this.createdAt = entry.getCreatedAt();
    }
}