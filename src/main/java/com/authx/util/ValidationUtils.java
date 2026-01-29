package com.authx.util;

import com.authx.constants.AppConstants;

import java.util.regex.Pattern;

/**
 * Validation Utilities
 * Provides validation methods for common use cases
 */
public final class ValidationUtils {
    
    private static final Pattern PASSWORD_PATTERN = Pattern.compile(AppConstants.PASSWORD_REGEX);
    
    private ValidationUtils() {
        // Private constructor to prevent instantiation
    }
    
    /**
     * Validate password strength
     * @param password password to validate
     * @return true if valid, false otherwise
     */
    public static boolean isValidPassword(String password) {
        if (password == null || password.isEmpty()) {
            return false;
        }
        return PASSWORD_PATTERN.matcher(password).matches();
    }
    
    /**
     * Validate password strength and throw exception if invalid
     * @param password password to validate
     * @throws IllegalArgumentException if password is invalid
     */
    public static void validatePassword(String password) {
        if (!isValidPassword(password)) {
            throw new IllegalArgumentException(AppConstants.PASSWORD_VALIDATION_MESSAGE);
        }
    }
    
    /**
     * Validate email format
     * @param email email to validate
     * @return true if valid, false otherwise
     */
    public static boolean isValidEmail(String email) {
        if (email == null || email.isEmpty()) {
            return false;
        }
        String emailRegex = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$";
        return Pattern.compile(emailRegex).matcher(email).matches();
    }
    
    /**
     * Generate OTP code
     * @return OTP string
     */
    public static String generateOTP() {
        return String.format("%0" + AppConstants.OTP_LENGTH + "d", 
                (int) (Math.random() * Math.pow(10, AppConstants.OTP_LENGTH)));
    }
    
    /**
     * Generate unique request ID
     * @return UUID string
     */
    public static String generateRequestId() {
        return java.util.UUID.randomUUID().toString();
    }
}
