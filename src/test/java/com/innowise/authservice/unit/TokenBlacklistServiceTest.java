package com.innowise.authservice.unit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import com.innowise.authservice.config.JwtProperties;
import com.innowise.authservice.security.TokenBlacklistService;
import com.innowise.authservice.utils.AuthTestDataFactory;

@ExtendWith(MockitoExtension.class)
@DisplayName("TokenBlacklistService unit tests")
class TokenBlacklistServiceTest {

    @Mock
    private StringRedisTemplate redis;

    @Mock
    private JwtProperties jwtProperties;

    @Mock
    private ValueOperations<String, String> valueOps;

    @InjectMocks
    private TokenBlacklistService tokenBlacklistService;

    private static final String KEY_PREFIX = AuthTestDataFactory.DEFAULT_BLACKLIST_KEY_PREFIX;

    @Test
    @DisplayName("getUserTokenVersion when userId is null returns 0")
    void getUserTokenVersion_whenUserIdNull_returnsZero() {
        long result = tokenBlacklistService.getUserTokenVersion(null);
        assertThat(result).isZero();
    }

    @Test
    @DisplayName("getUserTokenVersion when value is null returns 0")
    void getUserTokenVersion_whenValueNull_returnsZero() {
        UUID userId = UUID.randomUUID();
        when(jwtProperties.getBlacklistKeyPrefix()).thenReturn(KEY_PREFIX);
        when(redis.opsForValue()).thenReturn(valueOps);
        when(valueOps.get(KEY_PREFIX + "user-ver:" + userId)).thenReturn(null);

        long result = tokenBlacklistService.getUserTokenVersion(userId);
        assertThat(result).isZero();
    }

    @Test
    @DisplayName("getUserTokenVersion when value is blank returns 0")
    void getUserTokenVersion_whenValueBlank_returnsZero() {
        UUID userId = UUID.randomUUID();
        when(jwtProperties.getBlacklistKeyPrefix()).thenReturn(KEY_PREFIX);
        when(redis.opsForValue()).thenReturn(valueOps);
        when(valueOps.get(KEY_PREFIX + "user-ver:" + userId)).thenReturn("   ");

        long result = tokenBlacklistService.getUserTokenVersion(userId);
        assertThat(result).isZero();
    }

    @Test
    @DisplayName("getUserTokenVersion when value is not a number returns 0")
    void getUserTokenVersion_whenValueNotNumber_returnsZero() {
        UUID userId = UUID.randomUUID();
        when(jwtProperties.getBlacklistKeyPrefix()).thenReturn(KEY_PREFIX);
        when(redis.opsForValue()).thenReturn(valueOps);
        when(valueOps.get(KEY_PREFIX + "user-ver:" + userId)).thenReturn("not-a-number");

        long result = tokenBlacklistService.getUserTokenVersion(userId);
        assertThat(result).isZero();
    }

    @Test
    @DisplayName("getUserTokenVersion when value is valid returns parsed long")
    void getUserTokenVersion_whenValueValid_returnsParsedLong() {
        UUID userId = UUID.randomUUID();
        when(jwtProperties.getBlacklistKeyPrefix()).thenReturn(KEY_PREFIX);
        when(redis.opsForValue()).thenReturn(valueOps);
        when(valueOps.get(KEY_PREFIX + "user-ver:" + userId)).thenReturn("42");

        long result = tokenBlacklistService.getUserTokenVersion(userId);
        assertThat(result).isEqualTo(42L);
    }

    @Test
    @DisplayName("incrementUserTokenVersion when userId is null returns 0")
    void incrementUserTokenVersion_whenUserIdNull_returnsZero() {
        long result = tokenBlacklistService.incrementUserTokenVersion(null);
        assertThat(result).isZero();
    }

    @Test
    @DisplayName("incrementUserTokenVersion when increment succeeds returns new value")
    void incrementUserTokenVersion_whenIncrementSucceeds_returnsNewValue() {
        UUID userId = UUID.randomUUID();
        when(jwtProperties.getBlacklistKeyPrefix()).thenReturn(KEY_PREFIX);
        when(redis.opsForValue()).thenReturn(valueOps);
        when(valueOps.increment(KEY_PREFIX + "user-ver:" + userId)).thenReturn(6L);

        long result = tokenBlacklistService.incrementUserTokenVersion(userId);
        assertThat(result).isEqualTo(6L);
    }

    @Test
    @DisplayName("incrementUserTokenVersion when increment returns null returns 0")
    void incrementUserTokenVersion_whenIncrementReturnsNull_returnsZero() {
        UUID userId = UUID.randomUUID();
        when(jwtProperties.getBlacklistKeyPrefix()).thenReturn(KEY_PREFIX);
        when(redis.opsForValue()).thenReturn(valueOps);
        when(valueOps.increment(KEY_PREFIX + "user-ver:" + userId)).thenReturn(null);

        long result = tokenBlacklistService.incrementUserTokenVersion(userId);
        assertThat(result).isZero();
    }
}
