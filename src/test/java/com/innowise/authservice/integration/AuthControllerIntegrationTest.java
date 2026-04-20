package com.innowise.authservice.integration;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import com.innowise.authservice.dto.request.LoginRequest;
import com.innowise.authservice.dto.request.RefreshRequest;
import com.innowise.authservice.dto.request.RegisterRequest;
import com.innowise.authservice.dto.request.ValidateRequest;
import com.innowise.authservice.dto.response.AuthResponse;
import com.innowise.authservice.dto.response.ErrorResponse;
import com.innowise.authservice.dto.response.RegisterResponse;
import com.innowise.authservice.dto.response.ValidateResponse;
import com.innowise.authservice.security.BearerTokenConstants;
import com.innowise.authservice.utils.AuthTestDataFactory;

@DisplayName("Auth API integration tests (Controller → Service → Repository → DB)")
class AuthControllerIntegrationTest extends AbstractIntegrationTest {

    private String uniqueLogin() {
        return "user-" + UUID.randomUUID() + "@example.com";
    }

    private RegisterResponse registerUser() {
        String login = uniqueLogin();
        RegisterRequest request = AuthTestDataFactory.buildRegisterRequest(login, "Password123");

        return webTestClient
            .post()
            .uri("/auth/register")
            .bodyValue(request)
            .exchange()
            .expectStatus().isCreated()
            .expectBody(RegisterResponse.class)
            .returnResult()
            .getResponseBody();
    }

    @Nested
    @DisplayName("POST /auth/register")
    class Register {

        @Test
        @DisplayName("creates user and returns 201 with tokens")
        void createsUser_andReturns201WithTokens() {
            String login = uniqueLogin();
            RegisterRequest request = AuthTestDataFactory.buildRegisterRequest(login, "Password123");

            RegisterResponse response = webTestClient
                .post()
                .uri("/auth/register")
                .bodyValue(request)
                .exchange()
                .expectStatus().isCreated()
                .expectBody(RegisterResponse.class)
                .returnResult()
                .getResponseBody();

            assertThat(response).isNotNull();
            assertThat(response.user()).isNotNull();
            assertThat(response.user().id()).isNotNull();
            assertThat(response.user().login()).isEqualTo(login.toLowerCase());
            assertThat(response.accessToken()).isNotNull();
            assertThat(response.refreshToken()).isNotNull();
            assertThat(response.tokenType()).isEqualTo(BearerTokenConstants.BEARER_TOKEN_TYPE);
        }

        @Test
        @DisplayName("when login already exists returns 409")
        void whenLoginExists_returns409() {
            RegisterResponse first = registerUser();

            RegisterRequest request = AuthTestDataFactory.buildRegisterRequest(first.user().login(), "Password123");

            webTestClient
                .post()
                .uri("/auth/register")
                .bodyValue(request)
                .exchange()
                .expectStatus().isEqualTo(HttpStatus.CONFLICT)
                .expectBody(ErrorResponse.class)
                .value(err -> assertThat(err.errorCode()).isEqualTo("USER_ALREADY_EXISTS"));
        }
    }

    @Nested
    @DisplayName("POST /auth/login")
    class Login {

        @Test
        @DisplayName("when valid credentials returns 200 and tokens")
        void whenValidCredentials_returns200AndTokens() {
            RegisterResponse registered = registerUser();
            LoginRequest request = AuthTestDataFactory.buildLoginRequest(registered.user().login(), "Password123");

            AuthResponse response = webTestClient
                .post()
                .uri("/auth/login")
                .bodyValue(request)
                .exchange()
                .expectStatus().isOk()
                .expectBody(AuthResponse.class)
                .returnResult()
                .getResponseBody();

            assertThat(response).isNotNull();
            assertThat(response.accessToken()).isNotNull();
            assertThat(response.refreshToken()).isNotNull();
            assertThat(response.expiresIn()).isGreaterThan(0);
        }

        @Test
        @DisplayName("when invalid password returns 401")
        void whenInvalidPassword_returns401() {
            RegisterResponse registered = registerUser();
            LoginRequest request = AuthTestDataFactory.buildLoginRequest(registered.user().login(), "WrongPassword");

            webTestClient
                .post()
                .uri("/auth/login")
                .bodyValue(request)
                .exchange()
                .expectStatus().isUnauthorized()
                .expectBody(ErrorResponse.class)
                .value(err -> assertThat(err.errorCode()).isEqualTo("BAD_CREDENTIALS"));
        }

        @Test
        @DisplayName("when user not found returns 401 with bad credentials")
        void whenUserNotFound_returns401WithBadCredentials() {
            LoginRequest request = AuthTestDataFactory.buildLoginRequest("nonexistent@example.com", "Password123");

            webTestClient
                .post()
                .uri("/auth/login")
                .bodyValue(request)
                .exchange()
                .expectStatus().isUnauthorized()
                .expectBody(ErrorResponse.class)
                .value(err -> assertThat(err.errorCode()).isEqualTo("BAD_CREDENTIALS"));
        }
    }

    @Nested
    @DisplayName("POST /auth/validate")
    class Validate {

        @Test
        @DisplayName("when valid token returns valid=true and user info")
        void whenValidToken_returnsValidTrue() {
            RegisterResponse registered = registerUser();

            ValidateRequest request = AuthTestDataFactory.buildValidateRequest(registered.accessToken());

            ValidateResponse response = webTestClient
                .post()
                .uri("/auth/validate")
                .bodyValue(request)
                .exchange()
                .expectStatus().isOk()
                .expectBody(ValidateResponse.class)
                .returnResult()
                .getResponseBody();

            assertThat(response).isNotNull();
            assertThat(response.valid()).isTrue();
            assertThat(response.userId()).isEqualTo(registered.user().id().toString());
            assertThat(response.roles()).isNotEmpty();
        }

        @Test
        @DisplayName("when invalid token returns valid=false")
        void whenInvalidToken_returnsValidFalse() {
            ValidateRequest request = AuthTestDataFactory.buildValidateRequest("invalid.token.here");

            ValidateResponse response = webTestClient
                .post()
                .uri("/auth/validate")
                .bodyValue(request)
                .exchange()
                .expectStatus().isOk()
                .expectBody(ValidateResponse.class)
                .returnResult()
                .getResponseBody();

            assertThat(response).isNotNull();
            assertThat(response.valid()).isFalse();
        }
    }

    @Nested
    @DisplayName("POST /auth/refresh")
    class Refresh {

        @Test
        @DisplayName("when valid refresh token returns new tokens")
        void whenValidRefreshToken_returnsNewTokens() {
            RegisterResponse registered = registerUser();
            RefreshRequest request = AuthTestDataFactory.buildRefreshRequest(registered.refreshToken());

            AuthResponse response = webTestClient
                .post()
                .uri("/auth/refresh")
                .bodyValue(request)
                .exchange()
                .expectStatus().isOk()
                .expectBody(AuthResponse.class)
                .returnResult()
                .getResponseBody();

            assertThat(response).isNotNull();
            assertThat(response.accessToken()).isNotNull();
            assertThat(response.refreshToken()).isNotNull();
            assertThat(response.refreshToken()).isNotEqualTo(registered.refreshToken());
        }
    }

    @Nested
    @DisplayName("POST /auth/logout")
    class Logout {

        @Test
        @DisplayName("when valid request returns 204")
        void whenValidRequest_returns204() {
            RegisterResponse registered = registerUser();
            RefreshRequest request = AuthTestDataFactory.buildRefreshRequest(registered.refreshToken());

            webTestClient
                .post()
                .uri("/auth/logout")
                .headers(h -> h.set("Authorization", BearerTokenConstants.BEARER_PREFIX + registered.accessToken()))
                .bodyValue(request)
                .exchange()
                .expectStatus().isNoContent();
        }
    }

    @Nested
    @DisplayName("DELETE /auth/{userId} and /auth/internal/{userId}")
    class DeleteUser {

        @Test
        @DisplayName("admin delete without token returns 403")
        void adminDelete_withoutToken_returns403() {
            RegisterResponse registered = registerUser();

            webTestClient
                .delete()
                .uri("/auth/{userId}", registered.user().id())
                .exchange()
                .expectStatus().isForbidden();
        }

        @Test
        @DisplayName("admin delete with user token returns 403")
        void adminDelete_withUserToken_returns403() {
            RegisterResponse registered = registerUser();

            webTestClient
                .delete()
                .uri("/auth/{userId}", registered.user().id())
                .headers(h -> h.set("Authorization", BearerTokenConstants.BEARER_PREFIX + registered.accessToken()))
                .exchange()
                .expectStatus().isForbidden();
        }

        @Test
        @DisplayName("internal delete without token returns 204 and user can no longer login")
        void internalDelete_withoutToken_returns204_andDisablesLogin() {
            RegisterResponse registered = registerUser();

            webTestClient
                .delete()
                .uri("/auth/internal/{userId}", registered.user().id())
                .exchange()
                .expectStatus().isNoContent();

            LoginRequest loginRequest = AuthTestDataFactory.buildLoginRequest(registered.user().login(), "Password123");

            webTestClient
                .post()
                .uri("/auth/login")
                .bodyValue(loginRequest)
                .exchange()
                .expectStatus().isUnauthorized()
                .expectBody(ErrorResponse.class)
                .value(err -> assertThat(err.errorCode()).isEqualTo("BAD_CREDENTIALS"));
        }
    }
}
