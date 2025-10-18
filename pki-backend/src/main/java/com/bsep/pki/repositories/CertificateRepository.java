package com.bsep.pki.repositories;

import com.bsep.pki.enums.CertificateType;
import com.bsep.pki.models.Certificate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.List;
import java.util.Optional;

public interface CertificateRepository extends JpaRepository<Certificate, Long> {
    Optional<Certificate> findBySerialNumber(String serialNumber);

    List<Certificate> findByIssuerSerialNumber(String issuerSerialNumber);

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
}
