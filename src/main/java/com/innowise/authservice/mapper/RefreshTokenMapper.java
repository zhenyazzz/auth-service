package com.innowise.authservice.mapper;

import org.mapstruct.Context;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

import com.innowise.authservice.config.JwtProperties;
import com.innowise.authservice.model.RefreshToken;
import com.innowise.authservice.model.User;

@Mapper(componentModel = "spring")
public interface RefreshTokenMapper {

    @Mapping(target = "id", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "revoked", constant = "false")
    @Mapping(target = "expiresAt", expression = "java(java.time.Instant.now().plusSeconds(jwtProperties.getRefreshTokenExpiry().toSeconds()))")
    RefreshToken toEntity(User user, String tokenHash, @Context JwtProperties jwtProperties);
}
