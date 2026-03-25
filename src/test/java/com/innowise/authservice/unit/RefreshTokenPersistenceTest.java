package com.innowise.authservice.unit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.innowise.authservice.config.JwtProperties;
import com.innowise.authservice.exception.refresh.RefreshTokenNotFoundException;
import com.innowise.authservice.mapper.RefreshTokenMapper;
import com.innowise.authservice.model.RefreshToken;
import com.innowise.authservice.model.User;
import com.innowise.authservice.repository.RefreshTokenRepository;
import com.innowise.authservice.service.impl.RefreshTokenPersistence;
import com.innowise.authservice.utils.RefreshTokenTestDataFactory;
import com.innowise.authservice.utils.UserTestDataFactory;

@ExtendWith(MockitoExtension.class)
@DisplayName("RefreshTokenPersistence")
class RefreshTokenPersistenceTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private RefreshTokenMapper refreshTokenMapper;

    @Mock
    private JwtProperties jwtProperties;

    @InjectMocks
    private RefreshTokenPersistence persistence;

    @Nested
    @DisplayName("save")
    class Save {

        @Test
        @DisplayName("maps user and SHA-256 hash of raw token, then saves entity")
        void mapsHashedTokenAndSaves() {
            User user = UserTestDataFactory.buildUser("persist@example.com");
            String raw = "raw-token-value";
            String expectedHash = sha256Hex(raw);
            RefreshToken entity = RefreshTokenTestDataFactory.buildValidRefreshToken(user);
            when(refreshTokenMapper.toEntity(eq(user), eq(expectedHash), eq(jwtProperties))).thenReturn(entity);

            persistence.save(user, raw);

            verify(refreshTokenMapper).toEntity(eq(user), eq(expectedHash), eq(jwtProperties));
            verify(refreshTokenRepository).save(entity);
        }
    }

    @Nested
    @DisplayName("findByRawToken")
    class FindByRawToken {

        @Test
        @DisplayName("returns token when repository finds hash")
        void whenPresent_returnsToken() {
            User user = UserTestDataFactory.buildUser();
            RefreshToken token = RefreshTokenTestDataFactory.buildValidRefreshToken(user);
            String raw = "lookup-token";
            String hash = sha256Hex(raw);
            when(refreshTokenRepository.findByTokenHash(hash)).thenReturn(Optional.of(token));

            RefreshToken result = persistence.findByRawToken(raw);

            assertThat(result).isSameAs(token);
        }

        @Test
        @DisplayName("looks up by SHA-256 hex of raw string (UTF-8)")
        void queriesRepositoryWithHashedValue() {
            String raw = "another-raw";
            String hash = sha256Hex(raw);
            User user = UserTestDataFactory.buildUser();
            RefreshToken token = RefreshTokenTestDataFactory.buildValidRefreshToken(user);
            when(refreshTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.of(token));

            persistence.findByRawToken(raw);

            ArgumentCaptor<String> hashCaptor = ArgumentCaptor.forClass(String.class);
            verify(refreshTokenRepository).findByTokenHash(hashCaptor.capture());
            assertThat(hashCaptor.getValue()).isEqualTo(hash);
        }

        @Test
        @DisplayName("throws when no row for hash")
        void whenEmpty_throwsRefreshTokenNotFoundException() {
            when(refreshTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.empty());

            assertThatThrownBy(() -> persistence.findByRawToken("missing"))
                    .isInstanceOf(RefreshTokenNotFoundException.class)
                    .hasMessageContaining("Refresh token not found");
        }
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
            throw new IllegalStateException(e);
        }
    }
}
