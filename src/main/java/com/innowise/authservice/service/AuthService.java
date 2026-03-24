package com.innowise.authservice.service;

import java.util.UUID;

import com.innowise.authservice.dto.request.LoginRequest;
import com.innowise.authservice.dto.request.RefreshRequest;
import com.innowise.authservice.dto.request.RegisterRequest;
import com.innowise.authservice.dto.request.ValidateRequest;
import com.innowise.authservice.dto.response.AuthResponse;
import com.innowise.authservice.dto.response.RegisterResponse;
import com.innowise.authservice.dto.response.ValidateResponse;
import com.innowise.authservice.security.TokenPayload;

public interface AuthService {

    AuthResponse login(LoginRequest request);

    RegisterResponse register(RegisterRequest registerRequest);

    ValidateResponse validate(ValidateRequest request);

    AuthResponse refreshToken(RefreshRequest request);

    void deleteUser(UUID userId);

    void activateUser(UUID userId);

    void logout(TokenPayload payload, String refreshToken);

}
