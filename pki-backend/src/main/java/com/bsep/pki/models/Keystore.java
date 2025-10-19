package com.bsep.pki.models;

import jakarta.persistence.*;
import lombok.Data;
@Entity
@Data
public class Keystore {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(nullable = false, length = 512)
    private String encryptedPassword;
}