package com.innowise.authservice.dto.response;

import java.util.List;

import com.innowise.authservice.model.enums.RoleName;

public record ValidateResponse(
        boolean valid,
        String userId,
        List<RoleName> roles
) {}
