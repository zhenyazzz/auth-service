package com.innowise.authservice.service.impl;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

import com.innowise.authservice.config.JwtProperties;
import com.innowise.authservice.exception.refresh.RefreshTokenNotFoundException;
import com.innowise.authservice.mapper.RefreshTokenMapper;
import com.innowise.authservice.model.RefreshToken;
import com.innowise.authservice.model.User;
import com.innowise.authservice.repository.RefreshTokenRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class RefreshTokenPersistence {

    private final RefreshTokenRepository refreshTokenRepository;
    private final RefreshTokenMapper refreshTokenMapper;
    private final JwtProperties props;

    @Transactional
    public void save(User user, String rawRefreshToken) {
        String tokenHash = sha256Hex(rawRefreshToken);
        RefreshToken entity = refreshTokenMapper.toEntity(user, tokenHash, props);
        refreshTokenRepository.save(entity);
    }

    @Transactional(readOnly = true)
    public RefreshToken findByRawToken(String rawRefreshToken) {
        String tokenHash = sha256Hex(rawRefreshToken);
        return refreshTokenRepository.findByTokenHash(tokenHash)
                .orElseThrow(() -> new RefreshTokenNotFoundException("Refresh token not found"));
    }

    @Transactional(readOnly = true)
    public RefreshToken findByRawTokenAndUserId(String rawRefreshToken, UUID userId) {
        String tokenHash = sha256Hex(rawRefreshToken);
        return refreshTokenRepository.findByTokenHashAndUserId(tokenHash, userId)
                .orElseThrow(() -> new RefreshTokenNotFoundException("Refresh token not found"));
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
