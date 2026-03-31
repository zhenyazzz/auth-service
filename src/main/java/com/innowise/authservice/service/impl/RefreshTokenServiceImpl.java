package com.innowise.authservice.service.impl;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

import com.innowise.authservice.exception.refresh.RefreshTokenInvalidException;
import com.innowise.authservice.exception.refresh.RefreshTokenNotFoundException;
import com.innowise.authservice.model.RefreshToken;
import com.innowise.authservice.model.User;
import com.innowise.authservice.repository.RefreshTokenRepository;
import com.innowise.authservice.security.RefreshTokenRotation;
import com.innowise.authservice.security.TokenPayload;
import com.innowise.authservice.service.RefreshTokenService;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class RefreshTokenServiceImpl implements RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final RefreshTokenPersistence persistence;
    private final SecureRandom secureRandom = new SecureRandom();

    @Override
    @Transactional
    public String generateRefreshToken(User user) {
        String rawRefreshToken = generateSecureToken();
        persistence.save(user, rawRefreshToken);
        return rawRefreshToken;
    }

    @Override
    @Transactional
    public RefreshTokenRotation rotateRefreshToken(String oldRawRefreshToken) {
        User user = loadValidUserOrThrow(oldRawRefreshToken);
        String newRefreshToken = generateSecureToken();
        persistence.save(user, newRefreshToken);
        revokeByRawToken(oldRawRefreshToken);
        return new RefreshTokenRotation(user, newRefreshToken);
    }

    @Override
    @Transactional(readOnly = true)
    public User validateAndGetUser(String rawRefreshToken) {
        return loadValidUserOrThrow(rawRefreshToken);
    }

    @Override
    @Transactional(readOnly = true)
    public boolean validate(String rawRefreshToken) {
        RefreshToken token = persistence.findByRawToken(rawRefreshToken);
        if (token.isRevoked()) {
            return false;
        }
        return !token.getExpiresAt().isBefore(Instant.now());
    }

    @Override
    @Transactional
    public void revoke(TokenPayload payload, String rawRefreshToken) {
        if (payload == null || payload.userId() == null) {
            throw new AccessDeniedException("Refresh token does not belong to authenticated principal");
        }
        RefreshToken token;
        try {
            token = persistence.findByRawTokenAndUserId(rawRefreshToken, payload.userId());
        } catch (RefreshTokenNotFoundException ex) {
            throw new AccessDeniedException("Refresh token does not belong to authenticated principal");
        }
        token.setRevoked(true);
        refreshTokenRepository.save(token);
    }

    @Override
    @Transactional
    public void revokeAllByUserId(UUID userId) {
        refreshTokenRepository.revokeAllActiveByUserId(userId);
    }

    private User loadValidUserOrThrow(String rawRefreshToken) {
        RefreshToken token;
        try {
            token = persistence.findByRawToken(rawRefreshToken);
        } catch (RefreshTokenNotFoundException e) {
            throw new RefreshTokenInvalidException("Refresh token is invalid", e);
        }
        if (token.isRevoked() || token.getExpiresAt().isBefore(Instant.now())) {
            throw new RefreshTokenInvalidException("Refresh token is invalid");
        }
        return token.getUser();
    }

    private void revokeByRawToken(String rawRefreshToken) {
        RefreshToken token = persistence.findByRawToken(rawRefreshToken);
        token.setRevoked(true);
        refreshTokenRepository.save(token);
    }

    private String generateSecureToken() {
        byte[] randomBytes = new byte[64];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }
}
