package com.bsep.pki.repositories;

import com.bsep.pki.models.Password;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface PasswordRepository extends JpaRepository<Password, Long> {
    List<Password> findByOwner_Id(UUID ownerId);
    List<Password> findByOwnerUsername(String email);


    // Pronađi lozinke koje su direktno podeljene sa određenim korisnikom (gde je on u sharedWith mapi)
    // Oprez: Pretraga unutar ElementCollection mape može biti neefikasna sa JpaRepository.
    // Bolja implementacija može zahtevati custom query ili preuzimanje svih lozinki i filtriranje u Javi.
    // Za demo/početak, možemo pretpostaviti da je ovo dovoljno.
    @Query("SELECT p FROM Password p JOIN p.sharedWith sp WHERE KEY(sp) = :userId")
    List<Password> findBySharedWithKey(@Param("userId") UUID userId);
}