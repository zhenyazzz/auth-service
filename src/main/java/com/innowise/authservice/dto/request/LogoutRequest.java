package com.innowise.authservice.dto.request;

import jakarta.validation.constraints.NotBlank;

public record LogoutRequest(
        @NotBlank(message = "refreshToken is required")
        String refreshToken
) {}

