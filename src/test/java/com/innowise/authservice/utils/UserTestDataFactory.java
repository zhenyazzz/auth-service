package com.innowise.authservice.utils;

import java.util.Set;
import java.util.UUID;

import lombok.experimental.UtilityClass;

import com.innowise.authservice.model.Role;
import com.innowise.authservice.model.User;
import com.innowise.authservice.model.enums.RoleName;
import com.innowise.authservice.model.enums.UserStatus;

@UtilityClass
public class UserTestDataFactory {

    public final String DEFAULT_LOGIN = "test@example.com";
    public final String DEFAULT_PASSWORD = "encoded-password";
    public final String DEFAULT_RAW_PASSWORD = "Password123";
    public final String WRONG_LOGIN = "wrong@example.com";
    public final String WRONG_PASSWORD = "wrong-password";

    public User buildUser() {
        return buildUser(UUID.randomUUID(), DEFAULT_LOGIN, UserStatus.ACTIVE);
    }

    public User buildUser(UUID id) {
        return buildUser(id, DEFAULT_LOGIN, UserStatus.ACTIVE);
    }

    public User buildUser(String login) {
        return buildUser(UUID.randomUUID(), login, UserStatus.ACTIVE);
    }

    public User buildUser(UserStatus status) {
        return buildUser(UUID.randomUUID(), DEFAULT_LOGIN, status);
    }

    public User buildUser(UUID id, String login, UserStatus status) {
        User user = new User();
        user.setId(id);
        user.setLogin(login);
        user.setPassword(DEFAULT_PASSWORD);
        user.setRoles(Set.of(buildRoleUser()));
        user.setStatus(status);
        return user;
    }

    public User buildActiveUser() {
        return buildUser(UserStatus.ACTIVE);
    }

    public User buildDeletedUser() {
        return buildUser(UserStatus.DELETED);
    }

    public User buildUserWithRoles(UUID id, String login, Role... roles) {
        User user = new User();
        user.setId(id);
        user.setLogin(login);
        user.setPassword(DEFAULT_PASSWORD);
        user.setRoles(Set.of(roles));
        user.setStatus(UserStatus.ACTIVE);
        return user;
    }

    public Role buildRoleUser() {
        return buildRole(RoleName.ROLE_USER);
    }

    public Role buildRoleAdmin() {
        return buildRole(RoleName.ROLE_ADMIN);
    }

    public Role buildRole(RoleName name) {
        Role role = new Role();
        role.setId(UUID.randomUUID());
        role.setName(name);
        return role;
    }
}
