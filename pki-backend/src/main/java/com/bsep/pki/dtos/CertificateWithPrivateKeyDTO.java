package com.bsep.pki.dtos;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class CertificateWithPrivateKeyDTO {
    private CertificateDetailsDTO certificate; // Detalji o sertifikatu
    private String privateKeyPem; // Privatni ključ enkodovan u PEM format
}
