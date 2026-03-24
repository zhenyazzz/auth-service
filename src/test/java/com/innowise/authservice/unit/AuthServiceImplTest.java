package com.innowise.authservice.unit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.innowise.authservice.config.JwtProperties;
import com.innowise.authservice.dto.request.LoginRequest;
import com.innowise.authservice.dto.request.RefreshRequest;
import com.innowise.authservice.dto.request.RegisterRequest;
import com.innowise.authservice.dto.request.ValidateRequest;
import com.innowise.authservice.dto.response.AuthResponse;
import com.innowise.authservice.dto.response.RegisterResponse;
import com.innowise.authservice.dto.response.ValidateResponse;
import com.innowise.authservice.exception.RoleNotFoundException;
import com.innowise.authservice.exception.user.UserNotFoundException;
import com.innowise.authservice.mapper.UserMapper;
import com.innowise.authservice.model.Role;
import com.innowise.authservice.model.User;
import com.innowise.authservice.model.enums.RoleName;
import com.innowise.authservice.model.enums.UserStatus;
import com.innowise.authservice.repository.RoleRepository;
import com.innowise.authservice.repository.UserRepository;
import com.innowise.authservice.security.RefreshTokenRotation;
import com.innowise.authservice.security.TokenPayload;
import com.innowise.authservice.service.JwtService;
import com.innowise.authservice.service.RefreshTokenService;
import com.innowise.authservice.service.impl.AuthServiceImpl;
import com.innowise.authservice.utils.AuthTestDataFactory;
import com.innowise.authservice.utils.UserTestDataFactory;

@ExtendWith(MockitoExtension.class)
@DisplayName("AuthServiceImpl unit tests")
public class AuthServiceImplTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private RefreshTokenService refreshTokenService;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtService jwtService;

    @Mock
    private JwtProperties jwtProperties;

    @Mock
    private UserMapper userMapper;

    @Mock
    private RoleRepository roleRepository;

    @InjectMocks
    private AuthServiceImpl authService;


    @Test
    @DisplayName("login when credentials are valid returns AuthResponse")
    void login_whenCredentialsValid_returnsAuthResponse() {
        User user = UserTestDataFactory.buildActiveUser();
        LoginRequest request = AuthTestDataFactory.buildLoginRequest();

        when(userRepository.findByEmailAndStatus(UserTestDataFactory.DEFAULT_EMAIL, UserStatus.ACTIVE))
            .thenReturn(Optional.of(user));
        when(passwordEncoder.matches(UserTestDataFactory.DEFAULT_RAW_PASSWORD, user.getPassword())).thenReturn(true);
        when(refreshTokenService.generateRefreshToken(user)).thenReturn(AuthTestDataFactory.DEFAULT_REFRESH_TOKEN);
        when(jwtService.generateAccessToken(user)).thenReturn(AuthTestDataFactory.DEFAULT_ACCESS_TOKEN);
        when(jwtProperties.getAccessTokenExpiry()).thenReturn(Duration.ofMinutes(15));

        AuthResponse result = authService.login(request);

        assertThat(result).isNotNull();
        assertThat(result.accessToken()).isEqualTo(AuthTestDataFactory.DEFAULT_ACCESS_TOKEN);
        assertThat(result.refreshToken()).isEqualTo(AuthTestDataFactory.DEFAULT_REFRESH_TOKEN);
        assertThat(result.expiresIn()).isEqualTo(900);
    }

    @Test
    @DisplayName("login when user not found throws BadCredentialsException")
    void login_whenUserNotFound_throwsBadCredentialsException() {
        LoginRequest request = AuthTestDataFactory.buildLoginRequest(UserTestDataFactory.WRONG_EMAIL, UserTestDataFactory.DEFAULT_RAW_PASSWORD);

        when(userRepository.findByEmailAndStatus(UserTestDataFactory.WRONG_EMAIL, UserStatus.ACTIVE))
            .thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.login(request))
            .isInstanceOf(BadCredentialsException.class)
            .hasMessageContaining("Invalid credentials");
    }

    @Test
    @DisplayName("login when password is invalid throws BadCredentialsException")
    void login_whenPasswordInvalid_throwsBadCredentialsException() {
        User user = UserTestDataFactory.buildActiveUser();
        LoginRequest request = AuthTestDataFactory.buildLoginRequest(UserTestDataFactory.DEFAULT_EMAIL, UserTestDataFactory.WRONG_PASSWORD);

        when(userRepository.findByEmailAndStatus(UserTestDataFactory.DEFAULT_EMAIL, UserStatus.ACTIVE))
            .thenReturn(Optional.of(user));
        when(passwordEncoder.matches(UserTestDataFactory.WRONG_PASSWORD, user.getPassword())).thenReturn(false);

        assertThatThrownBy(() -> authService.login(request))
            .isInstanceOf(BadCredentialsException.class)
            .hasMessageContaining("Invalid credentials");
    }

    @Test
    @DisplayName("register when valid returns RegisterResponse")
    void register_whenValid_returnsRegisterResponse() {
        RegisterRequest request = AuthTestDataFactory.buildRegisterRequest();
        Role role = UserTestDataFactory.buildRoleUser();
        User savedUser = UserTestDataFactory.buildUser();

        when(roleRepository.findByName(RoleName.ROLE_USER)).thenReturn(Optional.of(role));
        when(userMapper.toEntity(any(), any(), any())).thenReturn(savedUser);
        when(userRepository.save(savedUser)).thenReturn(savedUser);
        when(refreshTokenService.generateRefreshToken(savedUser)).thenReturn(AuthTestDataFactory.DEFAULT_REFRESH_TOKEN);
        when(jwtService.generateAccessToken(savedUser)).thenReturn(AuthTestDataFactory.DEFAULT_ACCESS_TOKEN);
        when(jwtProperties.getAccessTokenExpiry()).thenReturn(Duration.ofMinutes(15));
        when(userMapper.toUserInfo(savedUser)).thenReturn(
            new RegisterResponse.UserInfo(savedUser.getId(), savedUser.getEmail(), java.util.List.of(RoleName.ROLE_USER))
        );

        RegisterResponse result = authService.register(request);

        assertThat(result).isNotNull();
        assertThat(result.accessToken()).isEqualTo(AuthTestDataFactory.DEFAULT_ACCESS_TOKEN);
        assertThat(result.refreshToken()).isEqualTo(AuthTestDataFactory.DEFAULT_REFRESH_TOKEN);
        assertThat(result.tokenType()).isEqualTo("Bearer");
        assertThat(result.user()).isNotNull();
        assertThat(result.user().email()).isEqualTo(UserTestDataFactory.DEFAULT_EMAIL);
    }

    @Test
    @DisplayName("register when role not found throws RoleNotFoundException")
    void register_whenRoleNotFound_throwsRoleNotFoundException() {
        RegisterRequest request = AuthTestDataFactory.buildRegisterRequest();

        when(roleRepository.findByName(RoleName.ROLE_USER)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.register(request))
            .isInstanceOf(RoleNotFoundException.class)
            .hasMessageContaining("Role not found with name");
    }

    @Test
    @DisplayName("validate when token is valid returns ValidateResponse with valid=true")
    void validate_whenTokenValid_returnsValidResponse() {
        UUID userId = UUID.randomUUID();
        ValidateRequest request = AuthTestDataFactory.buildValidateRequest();
        TokenPayload payload = AuthTestDataFactory.buildTokenPayload(userId);

        when(jwtService.validateAndExtract(AuthTestDataFactory.DEFAULT_ACCESS_TOKEN)).thenReturn(payload);

        ValidateResponse result = authService.validate(request);

        assertThat(result.valid()).isTrue();
        assertThat(result.userId()).isEqualTo(userId.toString());
        assertThat(result.roles()).contains(RoleName.ROLE_USER);
    }

    @Test
    @DisplayName("validate when token is invalid returns ValidateResponse with valid=false")
    void validate_whenTokenInvalid_returnsInvalidResponse() {
        ValidateRequest request = AuthTestDataFactory.buildValidateRequest(AuthTestDataFactory.INVALID_TOKEN);

        when(jwtService.validateAndExtract(AuthTestDataFactory.INVALID_TOKEN)).thenThrow(new RuntimeException("Invalid token"));

        ValidateResponse result = authService.validate(request);

        assertThat(result.valid()).isFalse();
        assertThat(result.userId()).isNull();
        assertThat(result.roles()).isEmpty();
    }

    @Test
    @DisplayName("refreshToken when valid returns AuthResponse")
    void refreshToken_whenValid_returnsAuthResponse() {
        User user = UserTestDataFactory.buildActiveUser();
        RefreshRequest request = AuthTestDataFactory.buildRefreshRequest();
        RefreshTokenRotation rotation = new RefreshTokenRotation(user, "new-refresh-token");

        when(refreshTokenService.rotateRefreshToken(AuthTestDataFactory.DEFAULT_REFRESH_TOKEN)).thenReturn(rotation);
        when(jwtService.generateAccessToken(user)).thenReturn("new-access-token");
        when(jwtProperties.getAccessTokenExpiry()).thenReturn(Duration.ofMinutes(15));

        AuthResponse result = authService.refreshToken(request);

        assertThat(result).isNotNull();
        assertThat(result.accessToken()).isEqualTo("new-access-token");
        assertThat(result.refreshToken()).isEqualTo("new-refresh-token");
    }

    @Test
    @DisplayName("refreshToken when token invalid throws exception from service")
    void refreshToken_whenTokenInvalid_throwsException() {
        RefreshRequest request = AuthTestDataFactory.buildRefreshRequest();

        when(refreshTokenService.rotateRefreshToken(AuthTestDataFactory.DEFAULT_REFRESH_TOKEN))
            .thenThrow(new RuntimeException("Invalid refresh token"));

        assertThatThrownBy(() -> authService.refreshToken(request))
            .isInstanceOf(RuntimeException.class)
            .hasMessageContaining("Invalid refresh token");
    }

    @Test
    @DisplayName("deleteUser when user exists sets status to DELETED and revokes tokens")
    void deleteUser_whenUserExists_setsStatusDeletedAndRevokesTokens() {
        UUID userId = UUID.randomUUID();
        User user = UserTestDataFactory.buildActiveUser();

        when(userRepository.findByIdAndStatus(userId, UserStatus.ACTIVE)).thenReturn(Optional.of(user));

        authService.deleteUser(userId);

        assertThat(user.getStatus()).isEqualTo(UserStatus.DELETED);
        verify(refreshTokenService).revokeAllByUserId(userId);
        verify(userRepository).save(user);
    }

    @Test
    @DisplayName("deleteUser when user not found throws UserNotFoundException")
    void deleteUser_whenUserNotFound_throwsUserNotFoundException() {
        UUID userId = UUID.randomUUID();

        when(userRepository.findByIdAndStatus(userId, UserStatus.ACTIVE)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.deleteUser(userId))
            .isInstanceOf(UserNotFoundException.class)
            .hasMessageContaining("User not found with id");
    }

    @Test
    @DisplayName("activateUser when user exists with DELETED status sets status to ACTIVE")
    void activateUser_whenUserExists_setsStatusActive() {
        UUID userId = UUID.randomUUID();
        User user = UserTestDataFactory.buildDeletedUser();

        when(userRepository.findByIdAndStatus(userId, UserStatus.DELETED)).thenReturn(Optional.of(user));

        authService.activateUser(userId);

        assertThat(user.getStatus()).isEqualTo(UserStatus.ACTIVE);
        verify(userRepository).save(user);
    }

    @Test
    @DisplayName("activateUser when user not found throws UserNotFoundException")
    void activateUser_whenUserNotFound_throwsUserNotFoundException() {
        UUID userId = UUID.randomUUID();

        when(userRepository.findByIdAndStatus(userId, UserStatus.DELETED)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.activateUser(userId))
            .isInstanceOf(UserNotFoundException.class)
            .hasMessageContaining("User not found with id");
    }

    @Test
    @DisplayName("logout revokes refresh token and access token")
    void logout_revokesTokens() {
        TokenPayload payload = AuthTestDataFactory.buildTokenPayload();

        authService.logout(payload, AuthTestDataFactory.DEFAULT_REFRESH_TOKEN);

        verify(refreshTokenService).revoke(AuthTestDataFactory.DEFAULT_REFRESH_TOKEN);
        verify(jwtService).revokeToken(payload);
    }
}
