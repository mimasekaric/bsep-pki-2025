package com.bsep.pki.dtos.requests;

import lombok.Data;

@Data
public class LoginRequestDTO {
    private String email;
    private String password;
    private String token;
    // private String recaptchaToken;
}
