package com.innowise.authservice.unit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import java.util.UUID;
import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
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

    @ParameterizedTest(name = "getUserTokenVersion when value is {0} returns 0")
    @MethodSource("getUserTokenVersion_invalidStoredValues")
    void getUserTokenVersion_whenStoredValueInvalid_returnsZero(String caseLabel, String storedValue) {
        UUID userId = UUID.randomUUID();
        when(jwtProperties.getBlacklistKeyPrefix()).thenReturn(KEY_PREFIX);
        when(redis.opsForValue()).thenReturn(valueOps);
        when(valueOps.get(KEY_PREFIX + "user-ver:" + userId)).thenReturn(storedValue);

        long result = tokenBlacklistService.getUserTokenVersion(userId);
        assertThat(result).isZero();
    }

    private static Stream<Arguments> getUserTokenVersion_invalidStoredValues() {
        return Stream.of(
                Arguments.of("null", null),
                Arguments.of("blank", "   "),
                Arguments.of("not a number", "not-a-number"));
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
