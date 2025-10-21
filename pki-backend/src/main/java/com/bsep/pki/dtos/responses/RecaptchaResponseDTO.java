package com.bsep.pki.dtos.responses;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class RecaptchaResponseDTO {
    private boolean success;
    @JsonProperty("error-codes")
    private String[] errorCodes;
}
