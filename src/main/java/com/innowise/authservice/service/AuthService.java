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

/**
 * Authentication and authorization use cases: credentials, JWT lifecycle, and admin user status.
 */
public interface AuthService {

    /**
     * Authenticates a user that exists with status {@code ACTIVE} and returns access and refresh tokens.
     *
     * @param request login identifier and password
     * @return access token, refresh token, and access token lifetime in seconds
     * @throws org.springframework.security.authentication.BadCredentialsException if login or password is wrong,
     *         or the user is not active (lookup is by active status only)
     */
    AuthResponse login(LoginRequest request);

    /**
     * Registers a new user and returns profile with access and refresh tokens.
     *
     * @param request login and password for the new account
     * @return created user info and tokens
     * @throws com.innowise.authservice.exception.user.UserAlreadyExistsException if login is already taken
     * @throws com.innowise.authservice.exception.RoleNotFoundException if the default role is missing from storage
     */
    RegisterResponse register(RegisterRequest request);

    /**
     * Validates a JWT access token string without requiring an {@code Authorization} header.
     *
     * @param request raw access token
     * @return {@code valid=true} with user id and roles when the token parses and passes checks; otherwise
     *         {@code valid=false} (no exception for invalid or expired tokens)
     */
    ValidateResponse validate(ValidateRequest request);

    /**
     * Rotates the refresh token and issues a new access token pair.
     *
     * @param request current refresh token
     * @return new access and refresh tokens
     * @throws com.innowise.authservice.exception.refresh.RefreshTokenInvalidException if the refresh token is unknown,
     *         revoked, or expired
     */
    AuthResponse refreshToken(RefreshRequest request);

    /**
     * Soft-deletes a user and revokes all refresh tokens for that user.
     *
     * @param userId target user id
     * @throws com.innowise.authservice.exception.user.UserNotFoundException if no active user exists for the id
     */
    void deleteUser(UUID userId);

    /**
     * Sets a previously soft-deleted user back to active.
     *
     * @param userId target user id
     * @throws com.innowise.authservice.exception.user.UserNotFoundException if no deleted user exists for the id
     */
    void activateUser(UUID userId);

    /**
     * Revokes the given refresh token and bumps the access-token version so current JWTs are invalidated.
     *
     * @param payload      principal from the validated access token
     * @param refreshToken refresh token presented in the body
     * @throws org.springframework.security.access.AccessDeniedException if the refresh token does not belong to
     *         the authenticated principal
     */
    void logout(TokenPayload payload, String refreshToken);

}
