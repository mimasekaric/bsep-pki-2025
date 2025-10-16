package com.bsep.pki.models;

import com.bsep.pki.enums.UserRole;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Entity
@AllArgsConstructor
@NoArgsConstructor
@Data
@Table(name="users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
     UUID id;
    @Column(nullable = false, unique = true)
     String name;
    @Column(nullable = false)
     String surname;
    @Column(nullable = false)
     String password;
    @Column(nullable = false, unique = true)
     String email;
    @Column(nullable = false)
     UserRole role;
    @Column(nullable = false)
     String organisation;
    @Column(nullable = false)
    private boolean enabled;

    private String verificationToken;

}
