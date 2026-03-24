package com.innowise.authservice.service;

import com.innowise.authservice.model.User;


public record RefreshTokenRotation(User user, String newRefreshToken) {}
