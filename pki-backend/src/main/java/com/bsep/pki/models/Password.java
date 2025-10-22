package com.bsep.pki.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Data
@NoArgsConstructor
@Table(name = "passwords")
public class Password {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "owner_id", nullable = false)
    private User owner; // Vlasnik PasswordEntry-a

    @JsonProperty("owner_username")
    @Column(nullable = false)
    private String ownerUsername;

    @Column(nullable = false)
    private String siteName; // Naziv sajta/servisa

    @Column(nullable = false)
    private String username; // Korisničko ime za sajt

    @Column(nullable = false, columnDefinition = "TEXT")
    private String encryptedPassword; // Enkriptovana lozinka (javnim ključem vlasnika)

    @Column(nullable = false)
    private LocalDateTime createdAt;

    // Mapa za deljene lozinke: Kljuc je UUID korisnika sa kojim je podeljeno, vrednost je enkriptovana lozinka za tog korisnika
    @ElementCollection
    @CollectionTable(name = "shared_passwords", joinColumns = @JoinColumn(name = "password_entry_id"))
    @MapKeyColumn(name = "shared_with_user_id")
    @Column(name = "encrypted_shared_password", columnDefinition = "TEXT")
    private java.util.Map<UUID, String> sharedWith = new java.util.HashMap<>();

    // Možeš dodati i metapodatke poput "last_modified_at", "last_modified_by" itd.

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
}