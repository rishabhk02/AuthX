package com.authx.controller;

import com.authx.dto.request.AssignPermissionsRequest;
import com.authx.dto.request.AssignRolesRequest;
import com.authx.dto.request.LoginRequest;
import com.authx.dto.request.RegisterRequest;
import com.authx.dto.response.ApiResponse;
import com.authx.dto.response.EmailVerificationResponse;
import com.authx.dto.response.LoginResponse;
import com.authx.dto.response.RegisterResponse;
import com.authx.dto.response.UserDetailsResponse;
import com.authx.service.AuthService;
import com.authx.service.UserService;
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
    private final AuthService authService;
    private final UserService userService;

    @PostMapping("/register")
    @Operation(summary = "Register a new user")
    public ResponseEntity<ApiResponse<RegisterResponse>> register(@RequestBody @Valid RegisterRequest request) {
        RegisterResponse response = authService.register(request);
        return ResponseEntity.status(201).body(ApiResponse.response("Registration successfully", "success", 201, response));
    }
    
    @PostMapping("/verify-email")
    @Operation(summary = "Verify user email")
    public ResponseEntity<ApiResponse<EmailVerificationResponse>> verifyEmail(@RequestParam String token) {
        authService.verifyEmail(token);
        return ResponseEntity.ok(ApiResponse.response("Email verification successful", "success", 200, new EmailVerificationResponse("Email Verified")));
    }
    
    @PostMapping("/login")
    @Operation(summary = "Login user")
    public ResponseEntity<ApiResponse<LoginResponse>> login(@RequestBody @Valid LoginRequest request) {
        LoginResponse response = authService.login(request);
        return ResponseEntity.ok(ApiResponse.response("Login successful", "success", 200, response));
    }

    @PostMapping("/assign-roles")
    @Operation(summary = "Assign roles to user", security = @SecurityRequirement(name = "bearerAuth"))
    @PreAuthorize("hasRole('SUPER_ADMIN') and hasAuthority('ASSIGN_ROLES')")
    public ResponseEntity<ApiResponse<UserDetailsResponse>> assignRolesToUser(@RequestBody @Valid AssignRolesRequest request) {
        UserDetailsResponse response = userService.assignRolesToUser(request);
        return ResponseEntity.ok(ApiResponse.response("Roles assigned successfully", "success", 200, response));
    }

    @PostMapping("/assign-permissions")
    @Operation(summary = "Assign permissions to user", security = @SecurityRequirement(name = "bearerAuth"))
    @PreAuthorize("hasRole('SUPER_ADMIN') and hasAuthority('ASSIGN_PERMISSIONS')")
    public ResponseEntity<ApiResponse<UserDetailsResponse>> assignPermissionsToUser(@RequestBody @Valid AssignPermissionsRequest request) {
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
}