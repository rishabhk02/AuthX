package com.authx.service.impl;

import com.authx.entity.Token;
import com.authx.enums.TokenPurpose;
import com.authx.entity.User;
import com.authx.repository.TokenRepository;
import com.authx.repository.UserRepository;
import com.authx.service.TokenBlacklistService;
import com.authx.service.interfaces.ITokenService;
import lombok.RequiredArgsConstructor;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.Date;

@Service
@RequiredArgsConstructor
public class TokenService implements ITokenService {
    private final TokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final TokenBlacklistService tokenBlacklistService;
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    @Value("${jwt.expiration.access}")
    private long accessExpirationMs;

    @Value("${jwt.expiration.refresh}")
    private long refreshExpirationMs;

    @Value("${jwt.expiration.email-verification}")
    private long emailVerificationExpirationMs;

    @Value("${jwt.expiration.password-reset}")
    private long passwordResetExpirationMs;

    public Token generateAccessToken(User user) {
        return generateToken(user, TokenPurpose.ACCESS, accessExpirationMs);
    }

    public Token generateRefreshToken(User user) {
        return generateToken(user, TokenPurpose.REFRESH, refreshExpirationMs);
    }

    public Token generateEmailVerificationToken(User user) {
        return generateToken(user, TokenPurpose.EMAIL_VERIFICATION, emailVerificationExpirationMs);
    }

    public Token generatePasswordResetToken(User user) {
        return generateToken(user, TokenPurpose.PASSWORD_RESET, passwordResetExpirationMs);
    }

    public Token generateToken(User user, TokenPurpose tokenPurpose, long durationInMilliSeconds) {
        Instant issuedAt = Instant.now();
        Instant expiry = issuedAt.plusMillis(durationInMilliSeconds);

        String jwtToken = Jwts.builder()
                .subject(user.getEmail())
                .claim("userId", user.getId())
                .claim("purpose", tokenPurpose.toString())
                .claim("tokenId", UUID.randomUUID().toString())
                .issuedAt(Date.from(issuedAt))
                .expiration(Date.from(expiry))
                .signWith(privateKey, Jwts.SIG.RS256) // Use private key for signing
                .compact();

        Token token = Token.builder()
                .token(jwtToken)
                .user(user)
                .purpose(tokenPurpose)
                .issuedAt(issuedAt)
                .expiryDate(expiry)
                .revoked(false)
                .build();

        return tokenRepository.save(token);
    }

    public boolean isTokenValid(String token) {
        // Check Redis blacklist first
        if (tokenBlacklistService != null && tokenBlacklistService.isBlacklisted(token)) return false;

        Optional<Token> tokenDetail = tokenRepository.findByToken(token);
        if (tokenDetail.isEmpty() || tokenDetail.get().getRevoked() || tokenDetail.get().getExpiryDate().isBefore(Instant.now())) return false;

        try {
            Claims claims = extractClaims(token);
            return claims.get("purpose", String.class).equals(tokenDetail.get().getPurpose().name());
        } catch (Exception ex) {
            return false;
        }

    }

    public Claims extractClaims(String token) {
        return Jwts.parser()
                .verifyWith(publicKey) // Use public key for verification
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public boolean revokeToken(String token) {
        return tokenRepository.findByToken(token).map(res -> {
            res.setRevoked(Boolean.TRUE);
            tokenRepository.save(res);

            if (tokenBlacklistService != null) {
                Instant expiry = res.getExpiryDate();
                tokenBlacklistService.blacklistToken(token, expiry);
            }

            return true;
        }).orElse(false);
    }

    public void revokeAllTokensForUser(User user) {
        // revoke access and refresh tokens
        for (TokenPurpose purpose : new TokenPurpose[]{TokenPurpose.ACCESS, TokenPurpose.REFRESH}) {
            var tokens = tokenRepository.findByUserAndPurposeAndRevokedFalse(user, purpose);
            if (tokens != null && !tokens.isEmpty()) {
                tokens.forEach(t -> t.setRevoked(Boolean.TRUE));
                tokenRepository.saveAll(tokens);

                if (tokenBlacklistService != null) {
                    tokens.forEach(t -> tokenBlacklistService.blacklistToken(t.getToken(), t.getExpiryDate()));
                }
            }
        }
    }

    public void revokeAllTokensForUserId(Long userId) {
        userRepository.findById(userId).ifPresent(this::revokeAllTokensForUser);
    }
}
