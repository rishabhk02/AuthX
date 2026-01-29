package com.authx.service.interfaces;

import com.authx.dto.request.LoginRequest;
import com.authx.dto.request.RegisterRequest;
import com.authx.dto.request.VerifyOTPRequest;
import com.authx.dto.response.LoginOTPResponse;
import com.authx.dto.response.LoginResponse;
import com.authx.dto.response.RegisterResponse;

/**
 * Authentication Service Interface
 */
public interface IAuthService {
    
    RegisterResponse register(RegisterRequest request);
    
    LoginOTPResponse login(LoginRequest request);
    
    LoginResponse verifyOTP(VerifyOTPRequest request);
    
    void resendVerificationEmail(String email);
    
    void sendPasswordResetEmail(String email);
    
    void resetPassword(String token, String newPassword);
    
    void updatePassword(Long userId, String currentPassword, String newPassword);
    
    void verifyEmail(String token);
}
