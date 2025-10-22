package com.bsep.pki.dtos.responses;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;


@Data
@NoArgsConstructor
@AllArgsConstructor
@Getter
public class UserOrganizationResponseDTO {
    private String organization;
}