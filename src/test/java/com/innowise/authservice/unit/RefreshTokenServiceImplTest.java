package com.innowise.authservice.unit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.innowise.authservice.config.JwtProperties;
import com.innowise.authservice.exception.refresh.RefreshTokenInvalidException;
import com.innowise.authservice.exception.refresh.RefreshTokenNotFoundException;
import com.innowise.authservice.mapper.RefreshTokenMapper;
import com.innowise.authservice.model.RefreshToken;
import com.innowise.authservice.model.User;
import com.innowise.authservice.repository.RefreshTokenRepository;
import com.innowise.authservice.security.RefreshTokenRotation;
import com.innowise.authservice.service.impl.RefreshTokenServiceImpl;
import com.innowise.authservice.utils.RefreshTokenTestDataFactory;
import com.innowise.authservice.utils.UserTestDataFactory;

@ExtendWith(MockitoExtension.class)
@DisplayName("RefreshTokenServiceImpl unit tests")
public class RefreshTokenServiceImplTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private JwtProperties jwtProperties;

    @Mock
    private RefreshTokenMapper refreshTokenMapper;

    @InjectMocks
    private RefreshTokenServiceImpl refreshTokenService;

    @Test
    @DisplayName("generateRefreshToken when user is not null generates a refresh token and saves it")
    void generateRefreshToken_whenUserIsNotNull_generatesRefreshTokenAndSavesIt() {
        User user = UserTestDataFactory.buildUser();
        RefreshToken entity = RefreshTokenTestDataFactory.buildValidRefreshToken(user);
        when(refreshTokenMapper.toEntity(any(), anyString(), any())).thenReturn(entity);

        String result = refreshTokenService.generateRefreshToken(user);

        assertThat(result).isNotNull();
        assertThat(result).isNotEmpty();
        verify(refreshTokenRepository).save(entity);
    }

    @Test
    @DisplayName("generateRefreshToken returns non-empty token with expected length")
    void generateRefreshToken_returnsNonEmptyTokenWithExpectedLength() {
        User user = UserTestDataFactory.buildUser("test2@example.com");
        when(refreshTokenMapper.toEntity(any(), anyString(), any()))
            .thenReturn(RefreshTokenTestDataFactory.buildValidRefreshToken(user));

        String result = refreshTokenService.generateRefreshToken(user);

        assertThat(result).isNotNull();
        assertThat(result).isNotEmpty();
        assertThat(result.length()).isGreaterThan(20);
    }

    @Test
    @DisplayName("rotateRefreshToken when token is valid returns new token and revokes old")
    void rotateRefreshToken_whenTokenValid_returnsNewTokenAndRevokesOld() {
        User user = UserTestDataFactory.buildUser("rotate@example.com");
        RefreshToken oldEntity = RefreshTokenTestDataFactory.buildValidRefreshToken(user);
        oldEntity.setExpiresAt(Instant.now().plusSeconds(3600));

        when(refreshTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.of(oldEntity));
        when(refreshTokenMapper.toEntity(any(), anyString(), any()))
            .thenReturn(RefreshTokenTestDataFactory.buildValidRefreshToken(user));

        RefreshTokenRotation result = refreshTokenService.rotateRefreshToken("old-refresh-token");

        assertThat(result).isNotNull();
        assertThat(result.user()).isEqualTo(user);
        assertThat(result.newRefreshToken()).isNotNull();
        assertThat(oldEntity.isRevoked()).isTrue();
        verify(refreshTokenRepository).save(oldEntity);
    }

    @Test
    @DisplayName("rotateRefreshToken when token not found throws RefreshTokenInvalidException")
    void rotateRefreshToken_whenTokenNotFound_throwsRefreshTokenInvalidException() {
        when(refreshTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> refreshTokenService.rotateRefreshToken("invalid-token"))
            .isInstanceOf(RefreshTokenInvalidException.class)
            .hasMessageContaining("Refresh token is invalid");
    }

    @Test
    @DisplayName("rotateRefreshToken when token is revoked throws RefreshTokenInvalidException")
    void rotateRefreshToken_whenTokenRevoked_throwsRefreshTokenInvalidException() {
        User user = UserTestDataFactory.buildUser("revoked@example.com");
        RefreshToken revokedEntity = RefreshTokenTestDataFactory.buildRevokedRefreshToken(user);

        when(refreshTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.of(revokedEntity));

        assertThatThrownBy(() -> refreshTokenService.rotateRefreshToken("revoked-token"))
            .isInstanceOf(RefreshTokenInvalidException.class)
            .hasMessageContaining("Refresh token is invalid");
    }

    @Test
    @DisplayName("rotateRefreshToken when token is expired throws RefreshTokenInvalidException")
    void rotateRefreshToken_whenTokenExpired_throwsRefreshTokenInvalidException() {
        User user = UserTestDataFactory.buildUser("expired@example.com");
        RefreshToken expiredEntity = RefreshTokenTestDataFactory.buildExpiredRefreshToken(user);

        when(refreshTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.of(expiredEntity));

        assertThatThrownBy(() -> refreshTokenService.rotateRefreshToken("expired-token"))
            .isInstanceOf(RefreshTokenInvalidException.class)
            .hasMessageContaining("Refresh token is invalid");
    }

    @Test
    @DisplayName("validateAndGetUser when token is valid returns user")
    void validateAndGetUser_whenTokenValid_returnsUser() {
        User user = UserTestDataFactory.buildUser("valid@example.com");
        RefreshToken validEntity = RefreshTokenTestDataFactory.buildValidRefreshToken(user);

        when(refreshTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.of(validEntity));

        User result = refreshTokenService.validateAndGetUser("valid-token");

        assertThat(result).isEqualTo(user);
    }

    @Test
    @DisplayName("validateAndGetUser when token not found throws RefreshTokenInvalidException")
    void validateAndGetUser_whenTokenNotFound_throwsRefreshTokenInvalidException() {
        when(refreshTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> refreshTokenService.validateAndGetUser("invalid-token"))
            .isInstanceOf(RefreshTokenInvalidException.class)
            .hasMessageContaining("Refresh token is invalid");
    }

    @Test
    @DisplayName("validateAndGetUser when token is revoked throws RefreshTokenInvalidException")
    void validateAndGetUser_whenTokenRevoked_throwsRefreshTokenInvalidException() {
        User user = UserTestDataFactory.buildUser("revoked@example.com");
        RefreshToken revokedEntity = RefreshTokenTestDataFactory.buildRevokedRefreshToken(user);

        when(refreshTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.of(revokedEntity));

        assertThatThrownBy(() -> refreshTokenService.validateAndGetUser("revoked-token"))
            .isInstanceOf(RefreshTokenInvalidException.class)
            .hasMessageContaining("Refresh token is invalid");
    }

    @Test
    @DisplayName("validateAndGetUser when token is expired throws RefreshTokenInvalidException")
    void validateAndGetUser_whenTokenExpired_throwsRefreshTokenInvalidException() {
        User user = UserTestDataFactory.buildUser("expired@example.com");
        RefreshToken expiredEntity = RefreshTokenTestDataFactory.buildExpiredRefreshToken(user);

        when(refreshTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.of(expiredEntity));

        assertThatThrownBy(() -> refreshTokenService.validateAndGetUser("expired-token"))
            .isInstanceOf(RefreshTokenInvalidException.class)
            .hasMessageContaining("Refresh token is invalid");
    }

    @Test
    @DisplayName("validate when token is valid returns true")
    void validate_whenTokenValid_returnsTrue() {
        User user = UserTestDataFactory.buildUser("valid@example.com");
        RefreshToken validEntity = RefreshTokenTestDataFactory.buildValidRefreshToken(user);

        when(refreshTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.of(validEntity));

        boolean result = refreshTokenService.validate("valid-token");

        assertThat(result).isTrue();
    }

    @Test
    @DisplayName("validate when token is revoked returns false")
    void validate_whenTokenRevoked_returnsFalse() {
        User user = UserTestDataFactory.buildUser("revoked@example.com");
        RefreshToken revokedEntity = RefreshTokenTestDataFactory.buildRevokedRefreshToken(user);

        when(refreshTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.of(revokedEntity));

        boolean result = refreshTokenService.validate("revoked-token");

        assertThat(result).isFalse();
    }

    @Test
    @DisplayName("validate when token is expired returns false")
    void validate_whenTokenExpired_returnsFalse() {
        User user = UserTestDataFactory.buildUser("expired@example.com");
        RefreshToken expiredEntity = RefreshTokenTestDataFactory.buildExpiredRefreshToken(user);

        when(refreshTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.of(expiredEntity));

        boolean result = refreshTokenService.validate("expired-token");

        assertThat(result).isFalse();
    }

    @Test
    @DisplayName("validate when token not found throws RefreshTokenNotFoundException")
    void validate_whenTokenNotFound_throwsRefreshTokenNotFoundException() {
        when(refreshTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> refreshTokenService.validate("invalid-token"))
            .isInstanceOf(RefreshTokenNotFoundException.class)
            .hasMessageContaining("Refresh token not found");
    }

    @Test
    @DisplayName("revoke when token exists marks it as revoked and saves")
    void revoke_whenTokenExists_marksAsRevokedAndSaves() {
        User user = UserTestDataFactory.buildUser("revoke@example.com");
        RefreshToken entity = RefreshTokenTestDataFactory.buildValidRefreshToken(user);

        when(refreshTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.of(entity));

        refreshTokenService.revoke("token-to-revoke");

        assertThat(entity.isRevoked()).isTrue();
        verify(refreshTokenRepository).save(entity);
    }

    @Test
    @DisplayName("revoke when token not found throws RefreshTokenNotFoundException")
    void revoke_whenTokenNotFound_throwsRefreshTokenNotFoundException() {
        when(refreshTokenRepository.findByTokenHash(anyString())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> refreshTokenService.revoke("invalid-token"))
            .isInstanceOf(RefreshTokenNotFoundException.class)
            .hasMessageContaining("Refresh token not found");
    }

    @Test
    @DisplayName("revokeAllByUserId calls repository method")
    void revokeAllByUserId_callsRepositoryMethod() {
        UUID userId = UUID.randomUUID();

        refreshTokenService.revokeAllByUserId(userId);

        verify(refreshTokenRepository).revokeAllActiveByUserId(userId);
    }
}
