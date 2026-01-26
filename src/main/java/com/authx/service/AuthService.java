package com.authx.service;

import com.authx.dto.request.EmailRequest;
import com.authx.dto.request.LoginRequest;
import com.authx.dto.request.RegisterRequest;
import com.authx.dto.request.VerifyOTPRequest;
import com.authx.dto.response.LoginOTPResponse;
import com.authx.dto.response.LoginResponse;
import com.authx.dto.response.RegisterResponse;
import com.authx.entity.OTPRequest;
import com.authx.entity.Permission;
import com.authx.entity.Role;
import com.authx.entity.Token;
import com.authx.entity.User;
import com.authx.enums.TokenPurpose;
import com.authx.repository.OTPRequestRepository;
import com.authx.repository.UserRepository;
import com.authx.util.EmailTemplates;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final TokenService tokenService;
    private final RabbitMQService rabbitMQService;
    private final PasswordEncoder passwordEncoder;
    private final DataInitializationService dataInitializationService;
    private final OTPRequestRepository otpRequestRepository;

    @Value("${email-verification-url}")
    private String emailVerificationUrl;

    @Value("${fe-login-url}")
    private String feLoginUrl;

    @Value("${password-reset-url}")
    private String passwordResetUrl;

    public RegisterResponse register(RegisterRequest request) {
        // Check if email already registered
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Email already registered");
        }

        // Validate password strength
        if (!isValidPassword(request.getPassword())) {
            throw new IllegalArgumentException("Password must be at least 8 characters long and include "
                    + "uppercase, lowercase, digit, and special character");
        }

        // Get default permission and role
        Permission defaultPermission = dataInitializationService.getDefaultPermission();
        Role defaultRole = dataInitializationService.getDefaultRole();

        Set<Permission> defaultPermissions = new HashSet<>();
        defaultPermissions.add(defaultPermission);

        Set<Role> defaultRoles = new HashSet<>();
        defaultRoles.add(defaultRole);

        // Create user with default permissions and role
        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .verified(false)
                .enabled(true)
                .userPermissions(defaultPermissions)
                .roles(defaultRoles)
                .build();

        user = userRepository.save(user);

        // Generate email verification token
        Token token = tokenService.generateEmailVerificationToken(user);

        String link = String.format("%s?token=%s", emailVerificationUrl, token.getToken());

        // Send email
        sendVerificationEmail(request.getEmail(), link);

        return RegisterResponse.builder()
                .message("Registration successful. Please check your email to verify your account.")
                .build();
    }

    public LoginOTPResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new BadCredentialsException("Invalid email or password"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new BadCredentialsException("Invalid email or password");
        }

        if (!user.getVerified()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Please verify your email before logging in");
        }

        if (!user.getEnabled()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Account is disabled");
        }

        // Generate 6-digit OTP
        String otp = String.format("%06d", (int) (Math.random() * 1000000));
        String requestId = java.util.UUID.randomUUID().toString();

        // Save OTP request (expires in 5 minutes)
        OTPRequest otpRequest = OTPRequest.builder()
                .requestId(requestId)
                .user(user)
                .otp(otp)
                .expiryTime(java.time.Instant.now().plusSeconds(300))
                .used(false)
                .createdAt(java.time.Instant.now())
                .build();

        otpRequestRepository.save(otpRequest);

        // Send OTP email
        sendOTPEmail(user.getEmail(), otp);

        return LoginOTPResponse.builder()
                .requestId(requestId)
                .build();
    }

    public LoginResponse verifyOTP(VerifyOTPRequest request) {
        OTPRequest otpRequest = otpRequestRepository.findByRequestIdAndUsedFalse(request.getRequestId())
                .orElseThrow(
                        () -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid or expired OTP request"));

        // Check if OTP is expired
        if (otpRequest.getExpiryTime().isBefore(java.time.Instant.now())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "OTP has expired");
        }

        // Verify OTP
        if (!otpRequest.getOtp().equals(request.getOtp())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid OTP");
        }

        // Mark OTP as used
        otpRequest.setUsed(true);
        otpRequestRepository.save(otpRequest);

        User user = otpRequest.getUser();

        // Generate tokens
        Token accessToken = tokenService.generateAccessToken(user);
        Token refreshToken = tokenService.generateRefreshToken(user);

        Set<String> roleNames = user.getRoles() != null
                ? new HashSet<>(user.getRoles()).stream().map(Role::getName).collect(Collectors.toSet())
                : new HashSet<>();

        Set<String> permissionNames = user.getUserPermissions() != null
                ? new HashSet<>(user.getUserPermissions()).stream().map(Permission::getName).collect(Collectors.toSet())
                : new HashSet<>();

        return LoginResponse.builder()
                .userId(user.getId())
                .email(user.getEmail())
                .accessToken(accessToken.getToken())
                .refreshToken(refreshToken.getToken())
                .roles(roleNames)
                .permissions(permissionNames)
                .build();
    }

    private void sendOTPEmail(String email, String otp) {
        String htmlContent = EmailTemplates.LOGIN_OTP_EMAIL
                .replace("${username}", email)
                .replace("${otpCode}", otp);

        EmailRequest emailRequest = EmailRequest.builder()
                .to(email)
                .subject("Your Login OTP - AuthX")
                .htmlBody(htmlContent)
                .build();

        rabbitMQService.sendEmail(emailRequest);
    }

    private void sendVerificationEmail(String email, String link) {
        String htmlContent = EmailTemplates.VERIFICATION_EMAIL
                .replace("${username}", email)
                .replace("${verificationUrl}", link);

        EmailRequest emailRequest = EmailRequest.builder()
                .to(email)
                .subject("Verify your email address - AuthX")
                .htmlBody(htmlContent)
                .build();

        rabbitMQService.sendEmail(emailRequest);
    }

    public void resendVerificationEmail(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        if (Boolean.TRUE.equals(user.getVerified())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email already verified");
        }

        Token token = tokenService.generateEmailVerificationToken(user);
        String link = String.format("%s?token=%s", emailVerificationUrl, token.getToken());
        sendVerificationEmail(email, link);
    }

    public void sendPasswordResetEmail(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        Token token = tokenService.generatePasswordResetToken(user);
        String link = String.format("%s?token=%s", passwordResetUrl, token.getToken());

        String htmlContent = EmailTemplates.PASSWORD_RESET_EMAIL
                .replace("${username}", email)
                .replace("${resetUrl}", link);

        EmailRequest emailRequest = EmailRequest.builder()
                .to(email)
                .subject("Reset your password - AuthX")
                .htmlBody(htmlContent)
                .build();

        rabbitMQService.sendEmail(emailRequest);
    }

    public void resetPassword(String token, String newPassword) {
        boolean isValid = tokenService.isTokenValid(token);
        if (!isValid) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid or expired token");
        }

        Claims claims = tokenService.extractClaims(token);
        if (!TokenPurpose.PASSWORD_RESET.toString().equals(claims.get("purpose").toString())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid token purpose");
        }

        String email = claims.getSubject();
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        // revoke used token
        tokenService.revokeToken(token);
    }

    public void updatePassword(Long userId, String currentPassword, String newPassword) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        if (!passwordEncoder.matches(currentPassword, user.getPassword())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Current password is incorrect");
        }

        if (currentPassword.equals(newPassword)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "New password must be different from current password");
        }

        if( !isValidPassword(newPassword)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Password must be at least 8 characters long and include "
                            + "uppercase, lowercase, digit, and special character");
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
    }

    public void verifyEmail(String token) {
        boolean isValid = tokenService.isTokenValid(token);
        if (!isValid) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid or expired token");
        }

        Claims claims = tokenService.extractClaims(token);
        if (!TokenPurpose.EMAIL_VERIFICATION.toString().equals(claims.get("purpose").toString())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid token purpose");
        }

        // Get user email from token and mark as verified
        String email = claims.getSubject();
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        user.setVerified(true);
        userRepository.save(user);

        log.info("Email verified for user: {}", email);
    }

    private boolean isValidPassword(String password) {
        String regex = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&#^()_+=\\-{}\\[\\]:;\"'<>,./~`|]).{8,}$";
        return password.matches(regex);
    }
}