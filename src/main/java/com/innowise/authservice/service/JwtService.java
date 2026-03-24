package com.innowise.authservice.service;

import com.innowise.authservice.model.User;
import com.innowise.authservice.security.TokenPayload;

public interface JwtService {
    String extractBearerToken(String authorization);
    String generateAccessToken(User user);
    TokenPayload validateAndExtract(String token);
    void revokeToken(TokenPayload payload);
}
