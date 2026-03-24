package com.innowise.authservice.dto.response;

public record  AuthResponse(
        String accessToken,
        String refreshToken,
        int expiresIn
) {}
