package com.innowise.authservice.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.innowise.authservice.model.RefreshToken;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    @EntityGraph(value = "RefreshToken.withUser")
    Optional<RefreshToken> findByTokenHash(String tokenHash);

    @EntityGraph(value = "RefreshToken.withUser")
    Optional<RefreshToken> findByTokenHashAndUserId(String tokenHash, UUID userId);

    
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("UPDATE RefreshToken rt SET rt.revoked = true WHERE rt.user.id = :userId AND rt.revoked = false")
    int revokeAllActiveByUserId(@Param("userId") UUID userId);

}
