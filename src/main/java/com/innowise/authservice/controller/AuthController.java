package com.innowise.authservice.controller;

import java.util.UUID;

import com.innowise.authservice.dto.request.LoginRequest;
import com.innowise.authservice.dto.request.LogoutRequest;
import com.innowise.authservice.dto.request.RefreshRequest;
import com.innowise.authservice.dto.request.RegisterRequest;
import com.innowise.authservice.dto.request.ValidateRequest;
import com.innowise.authservice.dto.response.AuthResponse;
import com.innowise.authservice.dto.response.RegisterResponse;
import com.innowise.authservice.dto.response.ValidateResponse;
import com.innowise.authservice.security.TokenPayload;
import com.innowise.authservice.service.AuthService;

import jakarta.validation.Valid;

import lombok.RequiredArgsConstructor;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * Authentication controller.
 * Handles login, registration, token operations, and user management.
 */
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * User login.
     *
     * @param request login data (username/email and password)
     * @return access and refresh tokens
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }

    /**
     * User registration.
     *
     * @param request registration data
     * @return created user and tokens
     */
    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.status(201).body(authService.register(request));
    }

    /**
     * Token validation.
     *
     * @param request token to validate
     * @return validation result
     */
    @PostMapping("/validate")
    public ResponseEntity<ValidateResponse> validate(@Valid @RequestBody ValidateRequest request) {
        return ResponseEntity.ok(authService.validate(request));
    }

    /**
     * Refresh tokens.
     *
     * @param request refresh token
     * @return new access and refresh tokens
     */
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshRequest request) {
        return ResponseEntity.ok(authService.refreshToken(request));
    }

    /**
     * Logout user.
     *
     * @param payload authenticated user data from token
     * @param request refresh token
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@AuthenticationPrincipal TokenPayload payload,
                                       @Valid @RequestBody LogoutRequest request) {
        authService.logout(payload, request.refreshToken());
        return ResponseEntity.noContent().build();
    }

    /**
     * Activate user (ADMIN only).
     *
     * @param userId user ID
     */
    @PatchMapping("/{userId}/activate")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> activateUser(@PathVariable UUID userId) {
        authService.activateUser(userId);
        return ResponseEntity.noContent().build();
    }

    /**
     * Delete user (ADMIN only).
     *
     * @param userId user ID
     */
    @DeleteMapping("/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteUser(@PathVariable UUID userId) {
        authService.deleteUser(userId);
        return ResponseEntity.noContent().build();
    }

    /**
     * Delete user for internal orchestration flow.
     *
     * @param userId user ID
     */
    @DeleteMapping("/internal/{userId}")
    public ResponseEntity<Void> deleteUserInternal(@PathVariable UUID userId) {
        authService.deleteUser(userId);
        return ResponseEntity.noContent().build();
    }

}
