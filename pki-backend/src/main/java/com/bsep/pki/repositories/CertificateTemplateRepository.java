package com.bsep.pki.repositories;

import com.bsep.pki.models.CertificateTemplate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CertificateTemplateRepository extends JpaRepository<CertificateTemplate, Long> {

    List<CertificateTemplate> findByIssuerSerialNumber(String issuerSerialNumber);

    Optional<CertificateTemplate> findByTemplateName(String templateName);
}
