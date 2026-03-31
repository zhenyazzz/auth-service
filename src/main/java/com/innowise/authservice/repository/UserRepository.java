package com.innowise.authservice.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.innowise.authservice.model.User;
import com.innowise.authservice.model.enums.UserStatus;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    boolean existsByLogin(String login);

    Optional<User> findByLoginAndStatus(String login, UserStatus status);

    Optional<User> findByIdAndStatus(UUID userId, UserStatus active);

}
