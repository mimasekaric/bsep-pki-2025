package com.bsep.pki.dtos.requests;

import lombok.Data;

@Data
public class ChangePasswordDTO {
    private String currentPassword;
    private String newPassword;
    private String confirmPassword;
}
