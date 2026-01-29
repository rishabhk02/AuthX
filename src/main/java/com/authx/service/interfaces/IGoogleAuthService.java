package com.authx.service.interfaces;

import com.authx.dto.response.LoginResponse;

/**
 * Google Authentication Service Interface
 */
public interface IGoogleAuthService {
    
    LoginResponse authenticateWithGoogle(String googleIdToken);
}
