package com.bsep.pki.mappers;


import com.bsep.pki.dtos.requests.UserRegistrationDTO;
import com.bsep.pki.dtos.responses.UserResponseDTO;
import com.bsep.pki.models.User;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.factory.Mappers;
import org.springframework.stereotype.Component;

@Mapper(componentModel = "spring")
public interface UserMapper {

    UserResponseDTO toDto(User user);

    @Mapping(target = "password", ignore = true)
    User toEntity(UserResponseDTO userResponseDTO);

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "role", ignore = true)
    User toEntity(UserRegistrationDTO registrationDTO);
}
