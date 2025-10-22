package com.bsep.pki.models;

import jakarta.persistence.*;
import lombok.Data;
import java.time.LocalDateTime;
import java.util.UUID;


@Entity
    @Data
    public class CSR {
        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private Long id;
        @ManyToOne
        private User owner;
        @Column(length = 4096)
        private String pemContent; // Sadržaj CSR fajla u PEM formatu
        @Enumerated(EnumType.STRING)
        private CsrStatus status;
        private LocalDateTime createdAt;
        private String rejectionReason;
        @Column(nullable = false)
        private UUID approverId;
        @Column(nullable = false)
        private LocalDateTime requestedValidFrom;
        @Column(nullable = false)
        private LocalDateTime requestedValidTo;

        public static enum CsrStatus {
            PENDING,
            APPROVED,
            REJECTED
        }
    }

