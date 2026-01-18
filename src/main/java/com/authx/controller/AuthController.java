package com.authx.controller;

import com.authx.dto.request.RegisterRequest;
import com.authx.dto.response.EmailVerificationResponse;
import com.authx.dto.response.RegisterResponse;
import com.authx.dto.response.ApiResponse;
import com.authx.service.AuthService;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Tag(name = "Auth", description = "Authentication & Email Verification APIs")
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<RegisterResponse>> register(@RequestBody @Valid RegisterRequest request) {
        RegisterResponse response = authService.register(request);
        return ResponseEntity.status(201).body(ApiResponse.response("Registration successfully", "success", 201, response));
    }

    @PostMapping("/verify-email")
    public ResponseEntity<ApiResponse<EmailVerificationResponse>> verifyEmail(@RequestParam String token) {
        // Verify email
        authService.verifyEmail(token);
        return ResponseEntity.status(200).body(ApiResponse.response("Email verification successfully", "success", 200, new EmailVerificationResponse("Email Verified")));
    }
}