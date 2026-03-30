package com.innowise.authservice.security;

public record IssuedAccessToken(String token, int expiresInSeconds) {
}
