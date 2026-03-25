package com.innowise.authservice.unit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import com.innowise.authservice.config.JwtProperties;
import com.innowise.authservice.model.User;
import com.innowise.authservice.model.enums.RoleName;
import com.innowise.authservice.security.TokenBlacklistService;
import com.innowise.authservice.security.TokenPayload;
import com.innowise.authservice.security.TokenRevokedException;
import com.innowise.authservice.service.impl.JwtServiceImpl;
import com.innowise.authservice.utils.AuthTestDataFactory;
import com.innowise.authservice.utils.UserTestDataFactory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.UUID;

@ExtendWith(MockitoExtension.class)
@DisplayName("JwtServiceImpl unit tests")
class JwtServiceImplTest {

    private static final String DEFAULT_JWT_SECRET_BASE64URL =
            "Y2hhbmdlLW1lLWluLXByb2R1Y3Rpb24tdGhpcy1pcy1hLTI1Ni1iaXQtc2VjcmV0LWtleS1mb3ItZGV2LW9ubHktY2hhbmdlLWl0";

    @Mock
    private JwtProperties jwtProperties;

    @Mock
    private TokenBlacklistService tokenBlacklistService;

    @InjectMocks
    private JwtServiceImpl jwtServiceImpl;


    @BeforeEach
    void wireSigningKey() {
        when(jwtProperties.getSecret()).thenReturn(DEFAULT_JWT_SECRET_BASE64URL);
        ReflectionTestUtils.invokeMethod(jwtServiceImpl, "initSigningKey");
    }

    @Test
    @DisplayName("extractBearerToken when authorization is null returns null")
    void extractBearerToken_whenAuthorizationIsNull_returnsNull() {
        String result = jwtServiceImpl.extractBearerToken(null);
        assertThat(result).isNull();
    }

    @Test
    @DisplayName("extractBearerToken when authorization starts with Bearer returns the token")
    void extractBearerToken_whenAuthorizationStartsWithBearer_returnsToken() {
        String result = jwtServiceImpl.extractBearerToken(AuthTestDataFactory.BEARER_PREFIX + "token");
        assertThat(result).isEqualTo("token");
    }

    @Test
    @DisplayName("extractBearerToken when authorization does not start with Bearer returns the authorization")
    void extractBearerToken_whenAuthorizationDoesNotStartWithBearer_returnsAuthorization() {
        String result = jwtServiceImpl.extractBearerToken("token");
        assertThat(result).isEqualTo("token");
    }

    @Test
    @DisplayName("generateAccessToken when user is not null generates an access token")
    void generateAccessToken_whenUserIsNotNull_generatesAccessToken() {
        User user = UserTestDataFactory.buildUser();

        when(jwtProperties.getIssuer()).thenReturn("test-issuer");
        when(jwtProperties.getAccessTokenExpiry()).thenReturn(Duration.ofHours(1));
        when(tokenBlacklistService.getUserTokenVersion(user.getId())).thenReturn(1L);

        String result = jwtServiceImpl.generateAccessToken(user);

        assertThat(result).isNotNull();
        assertThat(result.split("\\.")).hasSize(3);
    }

    @Test
    @DisplayName("generateAccessToken includes correct claims in token")
    void generateAccessToken_includesCorrectClaims() {
        User user = UserTestDataFactory.buildUserWithRoles(
            UUID.randomUUID(),
            UserTestDataFactory.DEFAULT_EMAIL,
            UserTestDataFactory.buildRoleUser(),
            UserTestDataFactory.buildRoleAdmin()
        );

        when(jwtProperties.getIssuer()).thenReturn("test-issuer");
        when(jwtProperties.getAccessTokenExpiry()).thenReturn(Duration.ofHours(2));
        when(tokenBlacklistService.getUserTokenVersion(user.getId())).thenReturn(5L);

        String token = jwtServiceImpl.generateAccessToken(user);

        assertThat(token).isNotNull();
    }

    @Test
    @DisplayName("validateAndExtract when token is valid returns TokenPayload")
    void validateAndExtract_whenTokenIsValid_returnsTokenPayload() {
        when(jwtProperties.getIssuer()).thenReturn("test-issuer");
        when(jwtProperties.getAccessTokenExpiry()).thenReturn(Duration.ofHours(1));

        User user = UserTestDataFactory.buildUser();
        when(tokenBlacklistService.getUserTokenVersion(user.getId())).thenReturn(1L);

        String token = jwtServiceImpl.generateAccessToken(user);

        TokenPayload payload = jwtServiceImpl.validateAndExtract(token);

        assertThat(payload).isNotNull();
        assertThat(payload.userId()).isEqualTo(user.getId());
        assertThat(payload.email()).isEqualTo(UserTestDataFactory.DEFAULT_EMAIL);
        assertThat(payload.roles()).contains(RoleName.ROLE_USER);
    }

    @Test
    @DisplayName("validateAndExtract when token is null throws IllegalArgumentException")
    void validateAndExtract_whenTokenIsNull_throwsException() {
        assertThatThrownBy(() -> jwtServiceImpl.validateAndExtract(null))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("validateAndExtract when token is malformed throws JwtException")
    void validateAndExtract_whenTokenIsMalformed_throwsException() {
        assertThatThrownBy(() -> jwtServiceImpl.validateAndExtract(AuthTestDataFactory.INVALID_TOKEN))
            .isInstanceOf(RuntimeException.class);
    }

    @Test
    @DisplayName("validateAndExtract when token is revoked throws TokenRevokedException")
    void validateAndExtract_whenTokenIsRevoked_throwsTokenRevokedException() {
        when(jwtProperties.getIssuer()).thenReturn("test-issuer");
        when(jwtProperties.getAccessTokenExpiry()).thenReturn(Duration.ofHours(1));

        User user = UserTestDataFactory.buildUser();

        when(tokenBlacklistService.getUserTokenVersion(user.getId()))
            .thenReturn(1L)
            .thenReturn(2L);

        String token = jwtServiceImpl.generateAccessToken(user);

        assertThatThrownBy(() -> jwtServiceImpl.validateAndExtract(token))
            .isInstanceOf(TokenRevokedException.class)
            .hasMessageContaining("Token has been revoked");
    }

    @Test
    @DisplayName("revokeToken when payload is valid increments token version")
    void revokeToken_whenPayloadIsValid_incrementsTokenVersion() {
        TokenPayload payload = AuthTestDataFactory.buildTokenPayload();

        when(tokenBlacklistService.incrementUserTokenVersion(payload.userId())).thenReturn(2L);

        jwtServiceImpl.revokeToken(payload);

        verify(tokenBlacklistService).incrementUserTokenVersion(payload.userId());
    }

    @Test
    @DisplayName("revokeToken when payload is null does nothing")
    void revokeToken_whenPayloadIsNull_doesNothing() {
        jwtServiceImpl.revokeToken(null);

        verify(tokenBlacklistService, never()).incrementUserTokenVersion(any());
    }

    @Test
    @DisplayName("revokeToken when userId is null does nothing")
    void revokeToken_whenUserIdIsNull_doesNothing() {
        TokenPayload payload = AuthTestDataFactory.buildTokenPayloadWithVersion(null, 1L);

        jwtServiceImpl.revokeToken(payload);

        verify(tokenBlacklistService, never()).incrementUserTokenVersion(any());
    }
}
