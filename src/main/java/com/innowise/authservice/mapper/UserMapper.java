package com.innowise.authservice.mapper;

import java.util.Set;

import org.mapstruct.Context;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

import org.springframework.security.crypto.password.PasswordEncoder;

import com.innowise.authservice.dto.request.RegisterRequest;
import com.innowise.authservice.dto.response.RegisterResponse;
import com.innowise.authservice.model.Role;
import com.innowise.authservice.model.User;

@Mapper(componentModel = "spring")
public interface UserMapper {

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "password", expression = "java(passwordEncoder.encode(request.password()))")
    @Mapping(target = "status", expression = "java(com.innowise.authservice.model.enums.UserStatus.ACTIVE)")
    User toEntity(RegisterRequest request, @Context PasswordEncoder passwordEncoder, Set<Role> roles);

    @Mapping(target = "roles", expression = "java(user.getRoles().stream().map(Role::getName).toList())")
    RegisterResponse.UserInfo toUserInfo(User user);
}
