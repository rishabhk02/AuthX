package com.authx.repository;

import com.authx.entity.OTPRequest;
import com.authx.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;

@Repository
public interface OTPRequestRepository extends JpaRepository<OTPRequest, Long> {
    Optional<OTPRequest> findByRequestIdAndUsedFalse(String requestId);
    
    void deleteByExpiryTimeBefore(Instant now);
    
    void deleteByUser(User user);
}
