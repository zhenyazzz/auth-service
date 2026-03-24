package com.innowise.authservice.service.impl;

import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.springframework.stereotype.Service;

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
import com.innowise.authservice.security.JwtService;
import com.innowise.authservice.security.TokenPayload;
import com.innowise.authservice.service.AuthService;
import com.innowise.authservice.service.RefreshTokenRotation;
import com.innowise.authservice.service.RefreshTokenService;

import jakarta.transaction.Transactional;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService{

    private final UserRepository userRepository;
    private final RefreshTokenService refreshTokenService;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final JwtProperties jwtProperties;
    private final UserMapper userMapper;
    private final RoleRepository roleRepository;

    @Override
    @Transactional
    public AuthResponse login(LoginRequest request) {
        User user = findByEmail(request.email());
        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            throw new BadCredentialsException("Invalid password");
        }
        String refreshToken = refreshTokenService.generateRefreshToken(user); 
        return buildAuthResponse(user, refreshToken);
    }

    @Override
    @Transactional
    public RegisterResponse register(RegisterRequest registerRequest) {
        Role role = roleRepository.findByName(RoleName.ROLE_USER)
                .orElseThrow(() -> new RoleNotFoundException("Role not found with name: " + RoleName.ROLE_USER));

        User user = userRepository.save(userMapper.toEntity(registerRequest, passwordEncoder, Set.of(role)));
        String refreshToken = refreshTokenService.generateRefreshToken(user); 
        return buildRegisterResponse(user, refreshToken);
    }

    private RegisterResponse buildRegisterResponse(User user, String refreshToken) {
        String accessToken = jwtService.generateAccessToken(user);
        return new RegisterResponse(
                userMapper.toUserInfo(user),
                accessToken,
                refreshToken,
                accessTokenExpiresInSeconds(),
                "Bearer");
    }

    @Override
    public ValidateResponse validate(ValidateRequest request) {
        try {
            TokenPayload payload = jwtService.validateAndExtract(request.token());
            return new ValidateResponse(true, payload.userId().toString(), payload.roles());
        } catch (RuntimeException ex) {
            return new ValidateResponse(false, null, List.of());
        }
    }

    @Override
    @Transactional
    public AuthResponse refreshToken(RefreshRequest request) {
        RefreshTokenRotation rotation = refreshTokenService.rotateRefreshToken(request.refreshToken());
        return buildAuthResponse(rotation.user(), rotation.newRefreshToken());
    }

    @Override
    @Transactional
    public void deleteUser(UUID userId) {
        User user = userRepository.findByIdAndStatus(userId, UserStatus.ACTIVE)
                .orElseThrow(() -> new UserNotFoundException("User not found with id: " + userId));
        user.setStatus(UserStatus.DELETED);
        refreshTokenService.revokeAllByUserId(userId);
        userRepository.save(user);
    }

    @Override
    @Transactional
    public void activateUser(UUID userId) {
        User user = userRepository.findByIdAndStatus(userId, UserStatus.DELETED)
                .orElseThrow(() -> new UserNotFoundException("User not found with id: " + userId));
        user.setStatus(UserStatus.ACTIVE);
        userRepository.save(user);
    }

    @Override
    @Transactional
    public void logout(TokenPayload payload, String refreshToken) {
        refreshTokenService.revoke(refreshToken);
        jwtService.revokeToken(payload);
    }

    private User findByEmail(String email) {
        return userRepository.findByEmailAndStatus(email, UserStatus.ACTIVE)
                .orElseThrow(() -> new UserNotFoundException("User not found with email: " + email));
    }

    private AuthResponse buildAuthResponse(User user, String refreshToken) {
        String accessToken = jwtService.generateAccessToken(user);
        return new AuthResponse(accessToken, refreshToken, accessTokenExpiresInSeconds());
    }

    private int accessTokenExpiresInSeconds() {
        return (int) jwtProperties.getAccessTokenExpiry().toSeconds();
    }

}
