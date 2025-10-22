package com.bsep.pki.repositories;

import com.bsep.pki.enums.CertificateType;
import com.bsep.pki.models.Certificate;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface CertificateRepository extends JpaRepository<Certificate, Long> {
    Optional<Certificate> findBySerialNumber(String serialNumber);

    List<Certificate> findByIssuerSerialNumber(String issuerSerialNumber);

    List<Certificate> findByTypeInAndRevokedFalseAndValidToAfter(List<CertificateType> types, LocalDateTime now);
    Optional<Certificate> findTopByOwner_IdAndTypeAndRevokedFalseAndValidToAfterOrderByValidFromDesc(
            UUID ownerId, CertificateType type, LocalDateTime now
    );
}
