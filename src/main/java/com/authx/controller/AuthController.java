package com.authx.controller;

import com.authx.dto.request.AssignPermissionsRequest;
import com.authx.dto.request.AssignRolesRequest;
import com.authx.dto.request.LoginRequest;
import com.authx.dto.request.RegisterRequest;
import com.authx.dto.request.VerifyOTPRequest;
import com.authx.dto.response.ApiResponse;
import com.authx.dto.response.EmailVerificationResponse;
import com.authx.dto.response.LoginOTPResponse;
import com.authx.dto.response.LoginResponse;
import com.authx.dto.response.RegisterResponse;
import com.authx.dto.response.UserDetailsResponse;
import com.authx.dto.request.ForgotPasswordRequest;
import com.authx.dto.request.GoogleLoginRequest;
import com.authx.dto.request.ResetPasswordRequest;
import com.authx.dto.request.UpdatePasswordRequest;
import com.authx.security.UserPrincipal;
import com.authx.service.interfaces.IAuthService;
import com.authx.service.interfaces.IGoogleAuthService;
import com.authx.service.interfaces.ITokenService;
import com.authx.service.interfaces.IUserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@Tag(name = "Auth", description = "Authentication & User Management APIs")
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final IAuthService authService;
    private final IGoogleAuthService googleAuthService;
    private final IUserService userService;
    private final ITokenService tokenService;

    @PostMapping("/register")
    @Operation(summary = "Register a new user")
    public ResponseEntity<ApiResponse<RegisterResponse>> register(@RequestBody @Valid RegisterRequest request) {
        RegisterResponse response = authService.register(request);
        return ResponseEntity.status(201)
                .body(ApiResponse.response("Registration successfully", "success", 201, response));
    }

    @PostMapping("/verify-email")
    @Operation(summary = "Verify user email")
    public ResponseEntity<ApiResponse<EmailVerificationResponse>> verifyEmail(@RequestParam String token) {
        authService.verifyEmail(token);
        return ResponseEntity.ok(ApiResponse.response("Email verification successful", "success", 200,
                new EmailVerificationResponse("Email Verified")));
    }

    @PostMapping("/google-login")
    @Operation(summary = "Authenticate with Google")
    public ResponseEntity<ApiResponse<LoginResponse>> googleLogin(@RequestBody @Valid GoogleLoginRequest request) {
        LoginResponse response = googleAuthService.authenticateWithGoogle(request.getIdToken());
        return ResponseEntity.ok(ApiResponse.response("Google authentication successful", "success", 200, response));
    }

    @PostMapping("/login")
    @Operation(summary = "Login user - sends OTP to email")
    public ResponseEntity<ApiResponse<LoginOTPResponse>> login(@RequestBody @Valid LoginRequest request) {
        LoginOTPResponse response = authService.login(request);
        return ResponseEntity.ok(ApiResponse.response("OTP sent to your email", "success", 200, response));
    }

    @PostMapping("/verify-otp")
    @Operation(summary = "Verify OTP and complete login")
    public ResponseEntity<ApiResponse<LoginResponse>> verifyOTP(@RequestBody @Valid VerifyOTPRequest request) {
        LoginResponse response = authService.verifyOTP(request);
        return ResponseEntity.ok(ApiResponse.response("Login successful", "success", 200, response));
    }

    @PostMapping("/resend-verification")
    @Operation(summary = "Resend verification email")
    public ResponseEntity<ApiResponse<Object>> resendVerification(@RequestParam String email) {
        authService.resendVerificationEmail(email);
        return ResponseEntity.ok(ApiResponse.response("Verification email resent", "success", 200, null));
    }

    @PostMapping("/forgot-password")
    @Operation(summary = "Send password reset email")
    public ResponseEntity<ApiResponse<Object>> forgotPassword(@RequestBody @Valid ForgotPasswordRequest request) {
        authService.sendPasswordResetEmail(request.getEmail());
        return ResponseEntity.ok(ApiResponse.response("Password reset email sent", "success", 200, null));
    }

    @PostMapping("/reset-password")
    @Operation(summary = "Reset password using token")
    public ResponseEntity<ApiResponse<Object>> resetPassword(@RequestBody @Valid ResetPasswordRequest request) {
        authService.resetPassword(request.getToken(), request.getNewPassword());
        return ResponseEntity.ok(ApiResponse.response("Password reset successful", "success", 200, null));
    }

    @PostMapping("/update-password")
    @Operation(summary = "Update password for authenticated user", security = @SecurityRequirement(name = "bearerAuth"))
    public ResponseEntity<ApiResponse<Object>> updatePassword(@AuthenticationPrincipal UserPrincipal principal,
            @RequestBody @Valid UpdatePasswordRequest request) {
        authService.updatePassword(principal.getId(), request.getCurrentPassword(), request.getNewPassword());
        return ResponseEntity.ok(ApiResponse.response("Password updated successfully", "success", 200, null));
    }

    @PostMapping("/assign-roles")
    @Operation(summary = "Assign roles to user", security = @SecurityRequirement(name = "bearerAuth"))
    @PreAuthorize("hasRole('SUPER_ADMIN') and hasAuthority('ASSIGN_ROLES')")
    public ResponseEntity<ApiResponse<UserDetailsResponse>> assignRolesToUser(
            @RequestBody @Valid AssignRolesRequest request) {
        UserDetailsResponse response = userService.assignRolesToUser(request);
        return ResponseEntity.ok(ApiResponse.response("Roles assigned successfully", "success", 200, response));
    }

    @PostMapping("/assign-permissions")
    @Operation(summary = "Assign permissions to user", security = @SecurityRequirement(name = "bearerAuth"))
    @PreAuthorize("hasRole('SUPER_ADMIN') and hasAuthority('ASSIGN_PERMISSIONS')")
    public ResponseEntity<ApiResponse<UserDetailsResponse>> assignPermissionsToUser(
            @RequestBody @Valid AssignPermissionsRequest request) {
        UserDetailsResponse response = userService.assignPermissionsToUser(request);
        return ResponseEntity.ok(ApiResponse.response("Permissions assigned successfully", "success", 200, response));
    }

    @GetMapping("/user/{userId}")
    @Operation(summary = "Get user details", security = @SecurityRequirement(name = "bearerAuth"))
    @PreAuthorize("hasRole('SUPER_ADMIN') or hasRole('ADMIN') or #userId == authentication.principal.id")
    public ResponseEntity<ApiResponse<UserDetailsResponse>> getUserDetails(@PathVariable Long userId) {
        UserDetailsResponse response = userService.getUserDetails(userId);
        return ResponseEntity.ok(ApiResponse.response("User details retrieved successfully", "success", 200, response));
    }

    @PostMapping("/logout")
    @Operation(summary = "Logout (revoke current token)", security = @SecurityRequirement(name = "bearerAuth"))
    public ResponseEntity<ApiResponse<Object>> logout(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            String token = header.substring(7);
            tokenService.revokeToken(token);
        }
        return ResponseEntity.ok(ApiResponse.response("Logged out", "success", 200, null));
    }

    @PostMapping("/logout-all")
    @Operation(summary = "Logout from all devices (revoke all tokens)", security = @SecurityRequirement(name = "bearerAuth"))
    public ResponseEntity<ApiResponse<Object>> logoutAll(@AuthenticationPrincipal UserPrincipal principal) {
        tokenService.revokeAllTokensForUserId(principal.getId());
        return ResponseEntity.ok(ApiResponse.response("Logged out from all devices", "success", 200, null));
    }
}