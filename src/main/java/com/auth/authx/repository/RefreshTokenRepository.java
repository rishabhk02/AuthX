package com.authx.repository;

import com.authx.entity.RefreshToken;
import com.auth.entity.User;
import org.springframework.data.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);

    void deleteByUser(User user);
}

