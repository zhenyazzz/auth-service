package com.innowise.authservice.dto.response;

import java.util.List;
import java.util.UUID;

import com.innowise.authservice.model.enums.RoleName;

public record RegisterResponse(
        UserInfo user,
        String accessToken,
        String refreshToken,
        int expiresIn,
        String tokenType
) {
    public record UserInfo(
            UUID id,
            String login,
            List<RoleName> roles
    ) {}
}
