package com.authx.service;

import java.time.Instant;

public interface TokenBlacklistService {
    void blacklistToken(String token, Instant expiry);

    boolean isBlacklisted(String token);
}
