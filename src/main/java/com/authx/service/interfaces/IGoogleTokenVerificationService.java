package com.authx.service.interfaces;

import com.authx.dto.response.GoogleUserInfo;

/**
 * Google Token Verification Service Interface
 */
public interface IGoogleTokenVerificationService {
    
    GoogleUserInfo verifyGoogleToken(String idToken);
}
