package com.bsep.pki.dtos.responses;

import lombok.Data;

@Data
public class LoginResponseDTO {

    private String accessToken;
    private String email;
    private boolean mustChangePassword;

    public LoginResponseDTO(String accessToken, String username, boolean mustChangePassword) {
        this.accessToken = accessToken;
        this.email = username;
        this.mustChangePassword = mustChangePassword;
    }
}
