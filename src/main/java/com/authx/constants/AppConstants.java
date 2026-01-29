package com.authx.constants;

/**
 * Application Constants
 * Centralized location for all application-wide constants
 */
public final class AppConstants {
    
    private AppConstants() {
        // Private constructor to prevent instantiation
    }
    
    // Password Validation
    public static final String PASSWORD_REGEX = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&#^()_+=\\-{}\\[\\]:;\"'<>,./~`|]).{8,}$";
    public static final String PASSWORD_VALIDATION_MESSAGE = "Password must be at least 8 characters long and include uppercase, lowercase, digit, and special character";
    
    // OTP
    public static final int OTP_LENGTH = 6;
    public static final long OTP_EXPIRY_SECONDS = 300; // 5 minutes
    
    // Email Templates
    public static final String EMAIL_TEMPLATE_USERNAME_PLACEHOLDER = "${username}";
    public static final String EMAIL_TEMPLATE_VERIFICATION_URL_PLACEHOLDER = "${verificationUrl}";
    public static final String EMAIL_TEMPLATE_OTP_PLACEHOLDER = "${otpCode}";
    public static final String EMAIL_TEMPLATE_RESET_URL_PLACEHOLDER = "${resetUrl}";
    
    // Email Subjects
    public static final String EMAIL_SUBJECT_VERIFICATION = "Verify your email address - AuthX";
    public static final String EMAIL_SUBJECT_OTP = "Your Login OTP - AuthX";
    public static final String EMAIL_SUBJECT_PASSWORD_RESET = "Reset your password - AuthX";
    
    // Response Messages
    public static final String MSG_REGISTRATION_SUCCESS = "Registration successful. Please check your email to verify your account.";
    public static final String MSG_EMAIL_VERIFIED = "Email verified successfully";
    public static final String MSG_EMAIL_ALREADY_VERIFIED = "Email already verified";
    public static final String MSG_EMAIL_ALREADY_REGISTERED = "Email already registered";
    public static final String MSG_USER_NOT_FOUND = "User not found";
    public static final String MSG_INVALID_CREDENTIALS = "Invalid email or password";
    public static final String MSG_ACCOUNT_NOT_VERIFIED = "Please verify your email before logging in";
    public static final String MSG_ACCOUNT_DISABLED = "Account is disabled";
    public static final String MSG_INVALID_TOKEN = "Invalid or expired token";
    public static final String MSG_OTP_EXPIRED = "OTP has expired";
    public static final String MSG_INVALID_OTP = "Invalid OTP";
    public static final String MSG_PASSWORD_RESET_SUCCESS = "Password reset successfully";
    public static final String MSG_PASSWORD_UPDATE_SUCCESS = "Password updated successfully";
    
    // Default Roles and Permissions
    public static final String DEFAULT_ROLE = "USER";
    public static final String DEFAULT_PERMISSION = "READ";
    
    // HTTP Status
    public static final String STATUS_SUCCESS = "success";
    public static final String STATUS_ERROR = "error";
}
