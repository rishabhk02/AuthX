package com.authx.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Entity
@Table(name = "otp_requests")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class OTPRequest {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String requestId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false)
    private String otp;

    @Column(nullable = false)
    private Instant expiryTime;

    @Column(nullable = false)
    private Boolean used;

    @Column(nullable = false)
    private Instant createdAt;
}
