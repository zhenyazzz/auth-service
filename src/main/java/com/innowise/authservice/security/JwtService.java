package com.innowise.authservice.security;

import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import com.innowise.authservice.config.JwtProperties;
import com.innowise.authservice.model.User;
import com.innowise.authservice.model.enums.RoleName;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import javax.crypto.SecretKey;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;
import java.util.List;

import jakarta.annotation.PostConstruct;

@Service
@RequiredArgsConstructor
public class JwtService {

    private final JwtProperties props;
    private final TokenBlacklistService blacklist;
    private SecretKey signingKey;

    @PostConstruct
    private void initSigningKey() {
        signingKey = Keys.hmacShaKeyFor(Decoders.BASE64URL.decode(props.getSecret()));
    }

    public String extractBearerToken(String authorization) {
        if (authorization == null) {
            return null;
        }
        return authorization.startsWith("Bearer ") ? authorization.substring(7) : authorization;
    }

    public String generateAccessToken(User user) {
        Instant now = Instant.now();
        List<String> roles = user.getRoles().stream()
            .map(r -> r.getName().name())
            .toList();
        long tokenVersion = blacklist.getUserTokenVersion(user.getId());
        return Jwts.builder()
            .issuer(props.getIssuer())
            .subject(user.getId().toString())
            .claim("email", user.getEmail())
            .claim("roles", roles)
            .claim("tokenVersion", tokenVersion)
            .issuedAt(Date.from(now))
            .expiration(Date.from(now.plusSeconds(props.getAccessTokenExpiry().toSeconds())))
            .signWith(signingKey, Jwts.SIG.HS512)
            .compact();
    }

    public TokenPayload validateAndExtract(String token) {
        Claims c = parseClaims(token);
        UUID userId = UUID.fromString(c.getSubject());
        long tokenVersion = validateTokenVersion(userId, c);
        @SuppressWarnings("unchecked")
        List<String> roles = c.get("roles", List.class);
        return new TokenPayload(
            userId,
            c.get("email", String.class),
            roles.stream().map(RoleName::valueOf).toList(),
            tokenVersion,
            c.getExpiration().toInstant()
        );
    }

    public void revokeToken(TokenPayload payload) {
        if (payload == null || payload.userId() == null) {
            return;
        }
        blacklist.incrementUserTokenVersion(payload.userId());
    }

    private long validateTokenVersion(UUID userId, Claims claims) {
        Number tokenVersionClaim = claims.get("tokenVersion", Number.class);
        long tokenVersion = tokenVersionClaim != null ? tokenVersionClaim.longValue() : 0L;
        long currentVersion = blacklist.getUserTokenVersion(userId);
        if (tokenVersion != currentVersion) {
            throw new TokenRevokedException("Token has been revoked");
        }
        return tokenVersion;
    }

    private Claims parseClaims(String token) {
        return Jwts.parser()
            .verifyWith(signingKey)
            .requireIssuer(props.getIssuer())
            .build()
            .parseSignedClaims(token)
            .getPayload();
    }
}
