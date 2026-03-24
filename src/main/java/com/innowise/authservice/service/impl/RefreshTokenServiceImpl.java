package com.innowise.authservice.service.impl;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

import com.innowise.authservice.config.JwtProperties;
import com.innowise.authservice.exception.refresh.RefreshTokenInvalidException;
import com.innowise.authservice.exception.refresh.RefreshTokenNotFoundException;
import com.innowise.authservice.mapper.RefreshTokenMapper;
import com.innowise.authservice.model.RefreshToken;
import com.innowise.authservice.model.User;
import com.innowise.authservice.repository.RefreshTokenRepository;
import com.innowise.authservice.service.RefreshTokenRotation;
import com.innowise.authservice.service.RefreshTokenService;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class RefreshTokenServiceImpl implements RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtProperties props;
    private final RefreshTokenMapper refreshTokenMapper;

    @Override
    @Transactional
    public String generateRefreshToken(User user) {
        String rawRefreshToken = generateSecureToken();
        save(user, rawRefreshToken);
        return rawRefreshToken;
    }

    @Transactional
    private void save(User user, String rawRefreshToken) {
        String tokenHash = sha256Hex(rawRefreshToken);
        RefreshToken entity = refreshTokenMapper.toEntity(user, tokenHash, props);
        refreshTokenRepository.save(entity);
    }

    @Override
    @Transactional
    public RefreshTokenRotation rotateRefreshToken(String oldRawRefreshToken) {
        User user = validateAndGetUser(oldRawRefreshToken);
        String newRefreshToken = generateRefreshToken(user); 
        revoke(oldRawRefreshToken);
        return new RefreshTokenRotation(user, newRefreshToken);
    }

    @Override
    @Transactional(readOnly = true)
    public User validateAndGetUser(String rawRefreshToken) {
        RefreshToken token;
        try {
            token = findByRawToken(rawRefreshToken);
        } catch (RefreshTokenNotFoundException e) {
            throw new RefreshTokenInvalidException("Refresh token is invalid", e);
        }
        if (token.isRevoked() || token.getExpiresAt().isBefore(Instant.now())) {
            throw new RefreshTokenInvalidException("Refresh token is invalid");
        }
        return token.getUser();
    }

    @Override
    @Transactional(readOnly = true)
    public boolean validate(String rawRefreshToken) {
        RefreshToken token = findByRawToken(rawRefreshToken);
        if (token.isRevoked()) {
            return false;
        }
        return !token.getExpiresAt().isBefore(Instant.now());
    }

    @Override
    @Transactional
    public void revoke(String rawRefreshToken) {
        RefreshToken token = findByRawToken(rawRefreshToken);
        token.setRevoked(true);
        refreshTokenRepository.save(token);
    }

    @Override
    @Transactional
    public void revokeAllByUserId(UUID userId) {
        refreshTokenRepository.revokeAllActiveByUserId(userId);
    }

    @Transactional(readOnly = true)
    private RefreshToken findByRawToken(String rawRefreshToken) {
        String tokenHash = sha256Hex(rawRefreshToken);
        return refreshTokenRepository.findByTokenHash(tokenHash)
                .orElseThrow(() -> new RefreshTokenNotFoundException("Refresh token not found"));
    }

    private String generateSecureToken() {
        byte[] randomBytes = new byte[64];
        new SecureRandom().nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    private static String sha256Hex(String raw) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(raw.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
