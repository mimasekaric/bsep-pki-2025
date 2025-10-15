package com.bsep.pki.dtos.responses;

import com.bsep.pki.enums.UserRole;
import lombok.Value;

import java.util.UUID;

@Value
public class UserResponseDTO {
     UUID id;
     String name;
     String surname;
     String email;
     UserRole role;
     String organisation;
}
