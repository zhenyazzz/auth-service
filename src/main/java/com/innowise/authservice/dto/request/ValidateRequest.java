package com.innowise.authservice.dto.request;

import jakarta.validation.constraints.NotBlank;

public record ValidateRequest(
        @NotBlank(message = "token is required")
        String token
) {}

