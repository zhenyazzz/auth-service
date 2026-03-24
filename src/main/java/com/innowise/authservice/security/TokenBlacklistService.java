package com.innowise.authservice.security;

import java.util.UUID;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

import com.innowise.authservice.config.JwtProperties;

@Service
@RequiredArgsConstructor
public class TokenBlacklistService {

    private final StringRedisTemplate redis;
    private final JwtProperties props;

    public long getUserTokenVersion(UUID userId) {
        if (userId == null) {
            return 0L;
        }
        String value = redis.opsForValue().get(userTokenVersionKey(userId));
        if (value == null || value.isBlank()) {
            return 0L;
        }
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException ex) {
            return 0L;
        }
    }

    public long incrementUserTokenVersion(UUID userId) {
        if (userId == null) {
            return 0L;
        }
        Long result = redis.opsForValue().increment(userTokenVersionKey(userId));
        return result != null ? result : 0L;
    }

    private String userTokenVersionKey(UUID userId) {
        return props.getBlacklistKeyPrefix() + "user-ver:" + userId;
    }
}
