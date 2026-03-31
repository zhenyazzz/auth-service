package com.innowise.authservice.security;

import com.innowise.authservice.model.User;


public record RefreshTokenRotation(User user, String newRefreshToken) {}
