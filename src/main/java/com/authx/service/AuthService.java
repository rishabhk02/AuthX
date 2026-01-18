package com.authx.service;

import com.authx.dto.request.EmailRequest;
import com.authx.dto.request.RegisterRequest;
import com.authx.dto.response.RegisterResponse;
import com.authx.dto.response.EmailVerificationResponse;
import com.authx.entity.Token;
import com.authx.enums.TokenPurpose;
import com.authx.entity.User;
import com.authx.repository.UserRepository;
import com.authx.util.EmailTemplates;
import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Value;
import lombok.*;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final TokenService tokenService;
    private final SendGridService sendGridService;
    private final PasswordEncoder passwordEncoder;

    @Value("${email-verification-url}")
    private String emailVerificationUrl;

    @Value("${fe-login-url")
    private String feLoginUrl;

    public RegisterResponse register(RegisterRequest request) {
        // Check if email already registered
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new IllegalArgumentException("Email already registered");
        }

        // Create user
        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .verified(false)
                .enabled(true)
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

    private void sendVerificationEmail(String email, String link) {
        String htmlContent = EmailTemplates.VERIFICATION_EMAIL
                .replace("${username}", email)
                .replace("${verificationUrl", link);

        EmailRequest emailRequest = EmailRequest.builder()
                .to(email)
                .subject("Verify your email address - AuthX")
                .htmlBody(htmlContent)
                .build();

        sendGridService.sendEmail(emailRequest);
        return;
    }

    public void verifyEmail(String token) {
        boolean isValid = tokenService.isTokenValid(token);
        if (!isValid) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid or expired token");
        }

        Claims claims = tokenService.extractClaims(token);
        if (claims.get("purpose") == TokenPurpose.EMAIL_VERIFICATION) {
            return;
        }
        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid token purpose");
    }
}