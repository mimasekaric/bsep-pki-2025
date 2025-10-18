package com.bsep.pki.repositories;

import com.bsep.pki.models.CSR;
import com.bsep.pki.models.Keystore;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CSRRepository extends JpaRepository<CSR, Long> {}

