package com.innowise.authservice.service;

import java.util.UUID;

import com.innowise.authservice.model.User;

public interface RefreshTokenService {

    String generateRefreshToken(User user);

    RefreshTokenRotation rotateRefreshToken(String oldRawRefreshToken);

    User validateAndGetUser(String rawRefreshToken);

    boolean validate(String refreshToken);

    void revoke(String refreshToken);

    void revokeAllByUserId(UUID userId);
}