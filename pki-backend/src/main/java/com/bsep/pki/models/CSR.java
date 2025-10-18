package com.bsep.pki.models;

import jakarta.persistence.*;
import lombok.Data;
import java.time.LocalDateTime;


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

        public static enum CsrStatus {
            PENDING,
            APPROVED,
            REJECTED
        }
    }

