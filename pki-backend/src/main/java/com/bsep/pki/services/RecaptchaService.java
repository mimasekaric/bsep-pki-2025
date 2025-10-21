package com.bsep.pki.services;

import com.bsep.pki.dtos.responses.RecaptchaResponseDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
@RequiredArgsConstructor
public class RecaptchaService {

    private final RestTemplate restTemplate;

    @Value("${google.recaptcha.secret}")
    private String recaptchaSecret;

    @Value("${google.recaptcha.verify-url}")
    private String recaptchaVerifyUrl;

    public boolean validateRecaptcha(String token) {
        if (token == null || token.isBlank()) {
            return false;
        }

        String url = String.format("%s?secret=%s&response=%s", recaptchaVerifyUrl, recaptchaSecret, token);

        try {
            RecaptchaResponseDTO response = restTemplate.postForObject(url, null, RecaptchaResponseDTO.class);
            return response != null && response.isSuccess();
        } catch (Exception e) {
            return false;
        }
    }
}