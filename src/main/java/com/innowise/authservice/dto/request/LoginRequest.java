package com.innowise.authservice.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record LoginRequest (
        @NotBlank(message = "login is required")
        @Email(message = "login is invalid")
        String login,
        @NotBlank(message = "password is required") 
        String password
) {}
