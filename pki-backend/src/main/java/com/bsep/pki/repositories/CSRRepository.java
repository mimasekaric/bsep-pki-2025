package com.bsep.pki.repositories;

import com.bsep.pki.models.CSR;
import com.bsep.pki.models.Keystore;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface CSRRepository extends JpaRepository<CSR, Long> {

    List<CSR> findByStatus(CSR.CsrStatus status);
    List<CSR> findByApproverIdAndStatus(UUID approverId, CSR.CsrStatus status);


}

