package com.authx.service.impl;

import com.authx.constants.AppConstants;
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
import com.authx.service.DataInitializationService;
import com.authx.service.RabbitMQService;
import com.authx.service.interfaces.IAuthService;
import com.authx.service.interfaces.ITokenService;
import com.authx.util.EmailTemplates;
import com.authx.util.ValidationUtils;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuthService implements IAuthService {
    private final UserRepository userRepository;
    private final ITokenService tokenService;
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
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email already registered");
        }

        // Validate password strength
        ValidationUtils.validatePassword(request.getPassword());

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
                .message(AppConstants.MSG_REGISTRATION_SUCCESS)
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

        // Generate OTP
        String otp = ValidationUtils.generateOTP();
        String requestId = ValidationUtils.generateRequestId();

        // Save OTP request (expires in 5 minutes)
        OTPRequest otpRequest = OTPRequest.builder()
                .requestId(requestId)
                .user(user)
                .otp(otp)
                .expiryTime(Instant.now().plusSeconds(AppConstants.OTP_EXPIRY_SECONDS))
                .used(false)
                .createdAt(Instant.now())
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
        if (otpRequest.getExpiryTime().isBefore(Instant.now())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, AppConstants.MSG_OTP_EXPIRED);
        }

        // Verify OTP
        if (!otpRequest.getOtp().equals(request.getOtp())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, AppConstants.MSG_INVALID_OTP);
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
                .replace(AppConstants.EMAIL_TEMPLATE_USERNAME_PLACEHOLDER, email)
                .replace(AppConstants.EMAIL_TEMPLATE_OTP_PLACEHOLDER, otp);

        EmailRequest emailRequest = EmailRequest.builder()
                .to(email)
                .subject(AppConstants.EMAIL_SUBJECT_OTP)
                .htmlBody(htmlContent)
                .build();

        rabbitMQService.sendEmail(emailRequest);
    }

    private void sendVerificationEmail(String email, String link) {
        String htmlContent = EmailTemplates.VERIFICATION_EMAIL
                .replace(AppConstants.EMAIL_TEMPLATE_USERNAME_PLACEHOLDER, email)
                .replace(AppConstants.EMAIL_TEMPLATE_VERIFICATION_URL_PLACEHOLDER, link);

        EmailRequest emailRequest = EmailRequest.builder()
                .to(email)
                .subject(AppConstants.EMAIL_SUBJECT_VERIFICATION)
                .htmlBody(htmlContent)
                .build();

        rabbitMQService.sendEmail(emailRequest);
    }

    public void resendVerificationEmail(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        if (Boolean.TRUE.equals(user.getVerified())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, AppConstants.MSG_EMAIL_ALREADY_VERIFIED);
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
                .replace(AppConstants.EMAIL_TEMPLATE_USERNAME_PLACEHOLDER, email)
                .replace(AppConstants.EMAIL_TEMPLATE_RESET_URL_PLACEHOLDER, link);

        EmailRequest emailRequest = EmailRequest.builder()
                .to(email)
                .subject(AppConstants.EMAIL_SUBJECT_PASSWORD_RESET)
                .htmlBody(htmlContent)
                .build();

        rabbitMQService.sendEmail(emailRequest);
    }

    public void resetPassword(String token, String newPassword) {
        if (!tokenService.isTokenValid(token)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid or expired token");
        }

        Claims claims = tokenService.extractClaims(token);
        if (!TokenPurpose.PASSWORD_RESET.toString().equals(claims.get("purpose").toString())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid token purpose");
        }

        ValidationUtils.validatePassword(newPassword);

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
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "New password must be different from current password");
        }

        ValidationUtils.validatePassword(newPassword);

        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
    }

    public void verifyEmail(String token) {
        if (!tokenService.isTokenValid(token)) {
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
}