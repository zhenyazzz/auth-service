package com.innowise.authservice.utils;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import lombok.experimental.UtilityClass;

import com.innowise.authservice.dto.request.LoginRequest;
import com.innowise.authservice.dto.request.RefreshRequest;
import com.innowise.authservice.dto.request.RegisterRequest;
import com.innowise.authservice.dto.request.ValidateRequest;
import com.innowise.authservice.dto.response.AuthResponse;
import com.innowise.authservice.dto.response.RegisterResponse;
import com.innowise.authservice.dto.response.ValidateResponse;
import com.innowise.authservice.model.enums.RoleName;
import com.innowise.authservice.security.TokenPayload;

@UtilityClass
public class AuthTestDataFactory {

    public final String DEFAULT_ACCESS_TOKEN = "test-access-token";
    public final String DEFAULT_REFRESH_TOKEN = "test-refresh-token";
    public final String INVALID_TOKEN = "invalid-token";
    public final String BEARER_PREFIX = "Bearer ";
    public final int DEFAULT_EXPIRES_IN = 900;
    public final String DEFAULT_BLACKLIST_KEY_PREFIX = "auth:jwt:blacklist:test:";

    public LoginRequest buildLoginRequest() {
        return new LoginRequest(UserTestDataFactory.DEFAULT_EMAIL, UserTestDataFactory.DEFAULT_RAW_PASSWORD);
    }

    public LoginRequest buildLoginRequest(String email, String password) {
        return new LoginRequest(email, password);
    }

    public RegisterRequest buildRegisterRequest() {
        return new RegisterRequest(UserTestDataFactory.DEFAULT_EMAIL, UserTestDataFactory.DEFAULT_RAW_PASSWORD);
    }

    public RegisterRequest buildRegisterRequest(String email, String password) {
        return new RegisterRequest(email, password);
    }

    public ValidateRequest buildValidateRequest() {
        return new ValidateRequest(DEFAULT_ACCESS_TOKEN);
    }

    public ValidateRequest buildValidateRequest(String token) {
        return new ValidateRequest(token);
    }

    public RefreshRequest buildRefreshRequest() {
        return new RefreshRequest(DEFAULT_REFRESH_TOKEN);
    }

    public RefreshRequest buildRefreshRequest(String refreshToken) {
        return new RefreshRequest(refreshToken);
    }

    public AuthResponse buildAuthResponse() {
        return new AuthResponse(DEFAULT_ACCESS_TOKEN, DEFAULT_REFRESH_TOKEN, DEFAULT_EXPIRES_IN);
    }

    public AuthResponse buildAuthResponse(String accessToken, String refreshToken) {
        return new AuthResponse(accessToken, refreshToken, DEFAULT_EXPIRES_IN);
    }

    public RegisterResponse buildRegisterResponse() {
        return buildRegisterResponse(UUID.randomUUID(), UserTestDataFactory.DEFAULT_EMAIL);
    }

    public RegisterResponse buildRegisterResponse(UUID userId, String email) {
        return new RegisterResponse(
            new RegisterResponse.UserInfo(userId, email, List.of(RoleName.ROLE_USER)),
            DEFAULT_ACCESS_TOKEN,
            DEFAULT_REFRESH_TOKEN,
            DEFAULT_EXPIRES_IN,
            "Bearer"
        );
    }

    public ValidateResponse buildValidValidateResponse() {
        return buildValidValidateResponse(UUID.randomUUID());
    }

    public ValidateResponse buildValidValidateResponse(UUID userId) {
        return new ValidateResponse(true, userId.toString(), List.of(RoleName.ROLE_USER));
    }

    public ValidateResponse buildInvalidValidateResponse() {
        return new ValidateResponse(false, null, List.of());
    }

    public TokenPayload buildTokenPayload() {
        return buildTokenPayload(UUID.randomUUID());
    }

    public TokenPayload buildTokenPayload(UUID userId) {
        return new TokenPayload(userId, UserTestDataFactory.DEFAULT_EMAIL, List.of(RoleName.ROLE_USER), 1L, Instant.now().plusSeconds(DEFAULT_EXPIRES_IN));
    }

    public TokenPayload buildTokenPayloadWithVersion(UUID userId, long version) {
        return new TokenPayload(userId, UserTestDataFactory.DEFAULT_EMAIL, List.of(RoleName.ROLE_USER), version, Instant.now().plusSeconds(DEFAULT_EXPIRES_IN));
    }

    public String buildAuthorizationHeader() {
        return BEARER_PREFIX + DEFAULT_ACCESS_TOKEN;
    }

    public String buildAuthorizationHeader(String token) {
        return BEARER_PREFIX + token;
    }
}
