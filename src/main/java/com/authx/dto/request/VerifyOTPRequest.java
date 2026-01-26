package com.authx.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class VerifyOTPRequest {
    
    @NotBlank(message = "Request ID is required")
    private String requestId;
    
    @NotBlank(message = "OTP is required")
    private String otp;
}
