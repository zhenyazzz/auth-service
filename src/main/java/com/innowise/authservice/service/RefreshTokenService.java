package com.innowise.authservice.service;

import java.util.UUID;

import com.innowise.authservice.model.User;
import com.innowise.authservice.security.RefreshTokenRotation;
import com.innowise.authservice.security.TokenPayload;

public interface RefreshTokenService {

    String generateRefreshToken(User user);

    RefreshTokenRotation rotateRefreshToken(String oldRawRefreshToken);

    User validateAndGetUser(String rawRefreshToken);

    boolean validate(String refreshToken);

    void revoke(TokenPayload payload, String refreshToken);

    void revokeAllByUserId(UUID userId);
}