package com.authx.repository;

import com.authx.entity.Token;
import com.authx.entity.User;
import com.authx.enums.TokenPurpose;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token, Long> {
    Optional<Token> findByToken(String token);

    List<Token> findByUserAndPurposeAndRevokedFalse(User user, TokenPurpose purpose);

    void deleteByUserAndPurpose(User user, TokenPurpose purpose);

    void deleteByToken(String token);
}

