package com.innowise.authservice.security;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import com.innowise.authservice.model.enums.RoleName;

public record TokenPayload(
        UUID userId,
        String email,
        List<RoleName> roles,
        long tokenVersion,
        Instant expiration
) {}

