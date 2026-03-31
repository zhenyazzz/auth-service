package com.innowise.authservice.unit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.access.AccessDeniedException;

import com.innowise.authservice.exception.refresh.RefreshTokenInvalidException;
import com.innowise.authservice.exception.refresh.RefreshTokenNotFoundException;
import com.innowise.authservice.model.RefreshToken;
import com.innowise.authservice.model.User;
import com.innowise.authservice.repository.RefreshTokenRepository;
import com.innowise.authservice.security.RefreshTokenRotation;
import com.innowise.authservice.security.TokenPayload;
import com.innowise.authservice.service.impl.RefreshTokenPersistence;
import com.innowise.authservice.service.impl.RefreshTokenServiceImpl;
import com.innowise.authservice.utils.RefreshTokenTestDataFactory;
import com.innowise.authservice.utils.UserTestDataFactory;

@ExtendWith(MockitoExtension.class)
@DisplayName("RefreshTokenServiceImpl")
class RefreshTokenServiceImplTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private RefreshTokenPersistence persistence;

    @InjectMocks
    private RefreshTokenServiceImpl refreshTokenService;

    @Nested
    @DisplayName("generateRefreshToken")
    class GenerateRefreshToken {

        @Test
        @DisplayName("generates non-empty token, persists via persistence, length suitable for URL-safe Base64")
        void generatesTokenAndCallsPersistenceSave() {
            User user = UserTestDataFactory.buildUser("gen@example.com");
            doNothing().when(persistence).save(eq(user), anyString());

            String result = refreshTokenService.generateRefreshToken(user);

            assertThat(result)
                    .isNotNull()
                    .isNotEmpty()
                    .hasSizeGreaterThan(20);
            verify(persistence).save(eq(user), anyString());
        }
    }

    @Nested
    @DisplayName("rotateRefreshToken")
    class RotateRefreshToken {

        @Test
        @DisplayName("valid old token: loads user, saves new token, revokes old; findByRawToken called twice for same raw")
        void whenValid_returnsRotationAndRevokesOld() {
            User user = UserTestDataFactory.buildUser("rotate@example.com");
            RefreshToken oldEntity = RefreshTokenTestDataFactory.buildValidRefreshToken(user);
            oldEntity.setExpiresAt(Instant.now().plusSeconds(3600));
            String oldRaw = "old-refresh-token";

            when(persistence.findByRawToken(oldRaw)).thenReturn(oldEntity);
            doNothing().when(persistence).save(eq(user), anyString());

            RefreshTokenRotation result = refreshTokenService.rotateRefreshToken(oldRaw);

            assertThat(result).isNotNull();
            assertThat(result.user()).isEqualTo(user);
            assertThat(result.newRefreshToken()).isNotNull();
            assertThat(oldEntity.isRevoked()).isTrue();
            verify(persistence, times(2)).findByRawToken(oldRaw);
            verify(persistence).save(eq(user), anyString());
            verify(refreshTokenRepository).save(oldEntity);
        }

        @Test
        @DisplayName("when token not found wraps as RefreshTokenInvalidException")
        void whenNotFound_throwsRefreshTokenInvalidException() {
            when(persistence.findByRawToken("invalid-token"))
                    .thenThrow(new RefreshTokenNotFoundException("Refresh token not found"));

            assertThatThrownBy(() -> refreshTokenService.rotateRefreshToken("invalid-token"))
                    .isInstanceOf(RefreshTokenInvalidException.class)
                    .hasMessageContaining("Refresh token is invalid");
        }

        @Test
        @DisplayName("when token revoked throws RefreshTokenInvalidException")
        void whenRevoked_throwsRefreshTokenInvalidException() {
            User user = UserTestDataFactory.buildUser("revoked@example.com");
            RefreshToken revokedEntity = RefreshTokenTestDataFactory.buildRevokedRefreshToken(user);

            when(persistence.findByRawToken("revoked-token")).thenReturn(revokedEntity);

            assertThatThrownBy(() -> refreshTokenService.rotateRefreshToken("revoked-token"))
                    .isInstanceOf(RefreshTokenInvalidException.class)
                    .hasMessageContaining("Refresh token is invalid");
        }

        @Test
        @DisplayName("when token expired throws RefreshTokenInvalidException")
        void whenExpired_throwsRefreshTokenInvalidException() {
            User user = UserTestDataFactory.buildUser("expired@example.com");
            RefreshToken expiredEntity = RefreshTokenTestDataFactory.buildExpiredRefreshToken(user);

            when(persistence.findByRawToken("expired-token")).thenReturn(expiredEntity);

            assertThatThrownBy(() -> refreshTokenService.rotateRefreshToken("expired-token"))
                    .isInstanceOf(RefreshTokenInvalidException.class)
                    .hasMessageContaining("Refresh token is invalid");
        }
    }

    @Nested
    @DisplayName("validateAndGetUser")
    class ValidateAndGetUser {

        @Test
        @DisplayName("returns user when token valid and not expired")
        void whenValid_returnsUser() {
            User user = UserTestDataFactory.buildUser("valid@example.com");
            RefreshToken validEntity = RefreshTokenTestDataFactory.buildValidRefreshToken(user);

            when(persistence.findByRawToken("valid-token")).thenReturn(validEntity);

            assertThat(refreshTokenService.validateAndGetUser("valid-token")).isEqualTo(user);
        }

        @Test
        @DisplayName("when not found wraps as RefreshTokenInvalidException")
        void whenNotFound_throwsRefreshTokenInvalidException() {
            when(persistence.findByRawToken("invalid-token"))
                    .thenThrow(new RefreshTokenNotFoundException("Refresh token not found"));

            assertThatThrownBy(() -> refreshTokenService.validateAndGetUser("invalid-token"))
                    .isInstanceOf(RefreshTokenInvalidException.class)
                    .hasMessageContaining("Refresh token is invalid");
        }

        @Test
        @DisplayName("when revoked throws RefreshTokenInvalidException")
        void whenRevoked_throwsRefreshTokenInvalidException() {
            User user = UserTestDataFactory.buildUser("revoked@example.com");
            RefreshToken revokedEntity = RefreshTokenTestDataFactory.buildRevokedRefreshToken(user);

            when(persistence.findByRawToken("revoked-token")).thenReturn(revokedEntity);

            assertThatThrownBy(() -> refreshTokenService.validateAndGetUser("revoked-token"))
                    .isInstanceOf(RefreshTokenInvalidException.class)
                    .hasMessageContaining("Refresh token is invalid");
        }

        @Test
        @DisplayName("when expired throws RefreshTokenInvalidException")
        void whenExpired_throwsRefreshTokenInvalidException() {
            User user = UserTestDataFactory.buildUser("expired@example.com");
            RefreshToken expiredEntity = RefreshTokenTestDataFactory.buildExpiredRefreshToken(user);

            when(persistence.findByRawToken("expired-token")).thenReturn(expiredEntity);

            assertThatThrownBy(() -> refreshTokenService.validateAndGetUser("expired-token"))
                    .isInstanceOf(RefreshTokenInvalidException.class)
                    .hasMessageContaining("Refresh token is invalid");
        }
    }

    @Nested
    @DisplayName("validate")
    class Validate {

        @Test
        @DisplayName("returns true when token active and not expired")
        void whenValid_returnsTrue() {
            User user = UserTestDataFactory.buildUser("valid@example.com");
            RefreshToken validEntity = RefreshTokenTestDataFactory.buildValidRefreshToken(user);

            when(persistence.findByRawToken("valid-token")).thenReturn(validEntity);

            assertThat(refreshTokenService.validate("valid-token")).isTrue();
        }

        @Test
        @DisplayName("returns false when revoked")
        void whenRevoked_returnsFalse() {
            User user = UserTestDataFactory.buildUser("revoked@example.com");
            RefreshToken revokedEntity = RefreshTokenTestDataFactory.buildRevokedRefreshToken(user);

            when(persistence.findByRawToken("revoked-token")).thenReturn(revokedEntity);

            assertThat(refreshTokenService.validate("revoked-token")).isFalse();
        }

        @Test
        @DisplayName("returns false when expired")
        void whenExpired_returnsFalse() {
            User user = UserTestDataFactory.buildUser("expired@example.com");
            RefreshToken expiredEntity = RefreshTokenTestDataFactory.buildExpiredRefreshToken(user);

            when(persistence.findByRawToken("expired-token")).thenReturn(expiredEntity);

            assertThat(refreshTokenService.validate("expired-token")).isFalse();
        }

        @Test
        @DisplayName("propagates RefreshTokenNotFoundException from persistence")
        void whenNotFound_throwsRefreshTokenNotFoundException() {
            when(persistence.findByRawToken("invalid-token"))
                    .thenThrow(new RefreshTokenNotFoundException("Refresh token not found"));

            assertThatThrownBy(() -> refreshTokenService.validate("invalid-token"))
                    .isInstanceOf(RefreshTokenNotFoundException.class)
                    .hasMessageContaining("Refresh token not found");
        }
    }

    @Nested
    @DisplayName("revoke")
    class Revoke {

        @Test
        @DisplayName("revokes token when owner matches principal")
        void whenOwnerMatches_revokesAndSaves() {
            UUID userId = UUID.randomUUID();
            User user = UserTestDataFactory.buildUser(userId, "owner@example.com", com.innowise.authservice.model.enums.UserStatus.ACTIVE);
            RefreshToken token = RefreshTokenTestDataFactory.buildValidRefreshToken(user);
            TokenPayload payload = new TokenPayload(userId, "owner@example.com", java.util.List.of(com.innowise.authservice.model.enums.RoleName.ROLE_USER), 1L, Instant.now().plusSeconds(60));

            when(persistence.findByRawTokenAndUserId("owned-token", userId)).thenReturn(token);

            refreshTokenService.revoke(payload, "owned-token");

            assertThat(token.isRevoked()).isTrue();
            verify(refreshTokenRepository).save(token);
        }

        @Test
        @DisplayName("throws 403-style exception when token belongs to another user")
        void whenOwnerMismatch_throwsAccessDeniedException() {
            UUID principalId = UUID.randomUUID();
            TokenPayload payload = new TokenPayload(principalId, "other@example.com", java.util.List.of(com.innowise.authservice.model.enums.RoleName.ROLE_USER), 1L, Instant.now().plusSeconds(60));

            when(persistence.findByRawTokenAndUserId("foreign-token", principalId))
                    .thenThrow(new RefreshTokenNotFoundException("Refresh token not found"));

            assertThatThrownBy(() -> refreshTokenService.revoke(payload, "foreign-token"))
                    .isInstanceOf(AccessDeniedException.class)
                    .hasMessageContaining("does not belong");
        }
    }

    @Nested
    @DisplayName("revokeAllByUserId")
    class RevokeAllByUserId {

        @Test
        @DisplayName("delegates to repository")
        void delegatesToRepository() {
            UUID userId = UUID.randomUUID();

            refreshTokenService.revokeAllByUserId(userId);

            verify(refreshTokenRepository).revokeAllActiveByUserId(userId);
        }
    }
}
