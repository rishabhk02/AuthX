package com.authx.service.interfaces;

import com.authx.entity.Token;
import com.authx.entity.User;
import com.authx.enums.TokenPurpose;
import io.jsonwebtoken.Claims;

/**
 * Token Service Interface
 */
public interface ITokenService {
    
    Token generateAccessToken(User user);
    
    Token generateRefreshToken(User user);
    
    Token generateEmailVerificationToken(User user);
    
    Token generatePasswordResetToken(User user);
    
    Token generateToken(User user, TokenPurpose tokenPurpose, long durationInMilliSeconds);
    
    boolean isTokenValid(String token);
    
    Claims extractClaims(String token);
    
    boolean revokeToken(String token);

    void revokeAllTokensForUser(User user);

    void revokeAllTokensForUserId(Long userId);
}
