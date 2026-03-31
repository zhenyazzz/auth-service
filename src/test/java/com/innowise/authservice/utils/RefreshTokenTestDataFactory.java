package com.innowise.authservice.utils;

import java.time.Instant;
import java.util.UUID;

import lombok.experimental.UtilityClass;

import com.innowise.authservice.model.RefreshToken;
import com.innowise.authservice.model.User;

@UtilityClass
public class RefreshTokenTestDataFactory {

    public final String DEFAULT_RAW_TOKEN = "default-refresh-token";
    public final String DEFAULT_TOKEN_HASH = "default-token-hash";
    public final long DEFAULT_EXPIRY_SECONDS = 604800; 

    public RefreshToken buildRefreshToken(User user) {
        return buildRefreshToken(UUID.randomUUID(), user, false);
    }

    public RefreshToken buildRefreshToken(User user, boolean revoked) {
        return buildRefreshToken(UUID.randomUUID(), user, revoked);
    }

    public RefreshToken buildRefreshToken(UUID id, User user, boolean revoked) {
        RefreshToken token = new RefreshToken();
        token.setId(id);
        token.setTokenHash(DEFAULT_TOKEN_HASH);
        token.setUser(user);
        token.setExpiresAt(Instant.now().plusSeconds(DEFAULT_EXPIRY_SECONDS));
        token.setRevoked(revoked);
        return token;
    }

    public RefreshToken buildValidRefreshToken(User user) {
        return buildRefreshToken(user, false);
    }

    public RefreshToken buildRevokedRefreshToken(User user) {
        return buildRefreshToken(user, true);
    }

    public RefreshToken buildExpiredRefreshToken(User user) {
        RefreshToken token = buildRefreshToken(user, false);
        token.setExpiresAt(Instant.now().minusSeconds(3600));
        return token;
    }
}
