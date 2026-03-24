package com.innowise.authservice.security;

import java.io.IOException;
import java.time.Instant;
import java.util.List;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import lombok.RequiredArgsConstructor;
import tools.jackson.databind.ObjectMapper;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.innowise.authservice.dto.response.ErrorResponse;

@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final ObjectMapper objectMapper;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorization == null || authorization.isBlank()) {
            filterChain.doFilter(request, response);
            return;
        }

        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            if (!authorization.startsWith("Bearer ")) {
                writeUnauthorized(response, "AUTHENTICATION_FAILED", "Invalid Authorization header");
                return;
            }

            String token = jwtService.extractBearerToken(authorization);
            if (token == null || token.isBlank()) {
                SecurityContextHolder.clearContext();
                writeUnauthorized(response, "AUTHENTICATION_FAILED", "Invalid or empty JWT");
                return;
            }

            TokenPayload payload = jwtService.validateAndExtract(token);

            List<SimpleGrantedAuthority> authorities = payload.roles().stream()
                .map(role -> new SimpleGrantedAuthority(role.name()))
                .toList();

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    payload,
                    null,
                    authorities
            );
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (RuntimeException ex) {
            SecurityContextHolder.clearContext();
            String errorCode = ex instanceof TokenRevokedException ? "TOKEN_REVOKED" : "AUTHENTICATION_FAILED";
            writeUnauthorized(response, errorCode, ex.getMessage() != null ? ex.getMessage() : "Invalid JWT");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private void writeUnauthorized(HttpServletResponse response, String errorCode, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        objectMapper.writeValue(response.getOutputStream(),
                new ErrorResponse(errorCode, message, Instant.now(), null));
    }
}
