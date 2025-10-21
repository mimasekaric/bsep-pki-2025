package com.bsep.pki.repositories;

import com.bsep.pki.enums.CertificateType;
import com.bsep.pki.models.Certificate;
import com.bsep.pki.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface CertificateRepository extends JpaRepository<Certificate, Long> {
    Optional<Certificate> findBySerialNumber(String serialNumber);

    List<Certificate> findByIssuerSerialNumber(String issuerSerialNumber);

    List<Certificate> findByTypeInAndRevokedFalseAndValidToAfter(List<CertificateType> types, LocalDateTime now);
    List<Certificate> findByOwnerIdAndTypeInAndRevokedFalseAndValidToAfter(
            UUID ownerId,
            List<CertificateType> types,
            LocalDateTime now
    );

    @Query("SELECT c FROM Certificate c WHERE c.type IN :caTypes AND c.revoked = false AND c.validTo > :currentDate")
    List<Certificate> findAllActiveCaCertificates(
            @Param("caTypes") List<CertificateType> caTypes,
            @Param("currentDate") LocalDateTime currentDate
    );

    @Query("SELECT c FROM Certificate c WHERE c.type IN :caTypes AND c.revoked = false AND c.validTo > :currentDate AND c.subjectDN LIKE :orgDnPattern")
    List<Certificate> findAllActiveCaCertificatesByOrganizationDN(
            @Param("orgDnPattern") String orgDnPattern,
            @Param("caTypes") List<CertificateType> caTypes,
            @Param("currentDate") LocalDateTime currentDate
    );

    @Query("SELECT c FROM Certificate c WHERE " +
            "c.owner = :owner AND " +
            "c.type IN :caTypes AND " +
            "c.validFrom <= :now AND " +
            "c.validTo >= :now AND " +
            "c.revoked = false")
    List<Certificate> findAllActiveCaCertificatesByOwner(
            @Param("owner") User owner,
            @Param("caTypes") List<CertificateType> caTypes,
            @Param("now") LocalDateTime now
    );

    List<Certificate> findByOwnerIdAndType(UUID ownerId, CertificateType type);

}
