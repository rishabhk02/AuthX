package com.authx.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;

@Service
@RequiredArgsConstructor
public class RedisTokenBlacklistService implements TokenBlacklistService {
    private final StringRedisTemplate redisTemplate;

    private static final String KEY_PREFIX = "blacklist:";

    @Override
    public void blacklistToken(String token, Instant expiry) {
        if (token == null || expiry == null) return;
        Instant now = Instant.now();
        if (expiry.isBefore(now)) return; // already expired

        Duration ttl = Duration.between(now, expiry);
        String key = KEY_PREFIX + token;
        redisTemplate.opsForValue().set(key, "1", ttl);
    }

    @Override
    public boolean isBlacklisted(String token) {
        if (token == null) return false;
        String key = KEY_PREFIX + token;
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }
}
