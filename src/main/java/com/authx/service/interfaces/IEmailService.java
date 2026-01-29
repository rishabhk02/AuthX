package com.authx.service.interfaces;

import com.authx.dto.request.EmailRequest;

/**
 * Email Service Interface
 */
public interface IEmailService {
    
    void sendEmail(EmailRequest emailRequest);
    
    void sendVerificationEmail(String email, String verificationLink);
    
    void sendOTPEmail(String email, String otp);
    
    void sendPasswordResetEmail(String email, String resetLink);
}
