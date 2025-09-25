package com.bsep.pki.models;

import com.bsep.pki.enums.UserRole;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
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
    @GeneratedValue
     UUID id;
     String name;
     String surname;
     String password;
     String email;
     UserRole role;
     String organisation;

}
