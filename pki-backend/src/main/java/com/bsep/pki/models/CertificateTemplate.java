package com.bsep.pki.models;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Entity
@Table(name = "certificate_templates")
@Getter
@Setter
@NoArgsConstructor
public class CertificateTemplate {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String templateName;

    @Column(nullable = false)
    private String issuerSerialNumber;

    @Column
    private String commonNameRegex;

    @Column
    private String sanRegex;

    @Column(nullable = false)
    private int ttlDays;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "template_key_usage", joinColumns = @JoinColumn(name = "template_id"))
    @Column(name = "key_usage")
    private List<String> keyUsage;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "template_extended_key_usage", joinColumns = @JoinColumn(name = "template_id"))
    @Column(name = "extended_key_usage")
    private List<String> extendedKeyUsage;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "owner_id", nullable = false)
    private User owner;
}