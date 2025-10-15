package com.bsep.pki.dtos.responses;

import lombok.Data;

@Data
public class LoginResponseDTO {

    private String accessToken;
    private String email;

    public LoginResponseDTO(String accessToken, String username) {
        this.accessToken = accessToken;
        this.email = username;
    }
}
