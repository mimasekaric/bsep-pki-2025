package com.bsep.pki.dtos.requests;

public record ResetPasswordRequest(String token, String newPassword) {
}