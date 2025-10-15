package com.bsep.pki.dtos.requests;

import lombok.Value;

@Value
public class UserRegistrationDTO {

     String name;
     String surname;
     String password;
     String email;
     String organisation;
}
