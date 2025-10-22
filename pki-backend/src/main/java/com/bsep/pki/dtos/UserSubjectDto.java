package com.bsep.pki.dtos;

import com.bsep.pki.models.User;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class UserSubjectDto {

    private UUID id;
    private String name;
    private String surname;
    private String role;
}
