package com.bsep.pki.dtos.requests;

import lombok.Data;

@Data
public class CAUserRegistrationDTO {
    private String firstName;
    private String lastName;
    private String email;
    private String organization;
}
