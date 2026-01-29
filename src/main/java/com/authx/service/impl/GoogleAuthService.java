package com.authx.service.impl;

import com.authx.dto.response.GoogleUserInfo;
import com.authx.dto.response.LoginResponse;
import com.authx.entity.Permission;
import com.authx.entity.Role;
import com.authx.entity.Token;
import com.authx.entity.User;
import com.authx.enums.AuthProvider;
import com.authx.integration.oauth.GoogleTokenVerificationService;
import com.authx.repository.UserRepository;
import com.authx.service.DataInitializationService;
import com.authx.service.interfaces.IGoogleAuthService;
import com.authx.service.interfaces.ITokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class GoogleAuthService implements IGoogleAuthService {
    
    private final UserRepository userRepository;
    private final GoogleTokenVerificationService googleTokenVerificationService;
    private final ITokenService tokenService;
    private final DataInitializationService dataInitializationService;
    
    public LoginResponse authenticateWithGoogle(String googleIdToken) {
        // Verify Google ID token
        GoogleUserInfo googleUserInfo = googleTokenVerificationService.verifyGoogleToken(googleIdToken);
        
        // Find or create user
        User user = findOrCreateGoogleUser(googleUserInfo);
        
        // Generate access token
        Token accessToken = tokenService.generateAccessToken(user);

        // Generate refresh token
        Token refreshToken = tokenService.generateRefreshToken(user);
        
        // Get user permissions and roles
        Set<String> permissions = user.getUserPermissions().stream()
                .map(permission -> permission.getName())
                .collect(Collectors.toSet());
        
        Set<String> roles = user.getRoles().stream()
                .map(role -> role.getName())
                .collect(Collectors.toSet());
        
        return LoginResponse.builder()
                .userId(user.getId())
                .email(user.getEmail())
                .accessToken(accessToken.getToken())
                .refreshToken(refreshToken.getToken())
                .roles(roles)
                .permissions(permissions)
                .build();
    }
    
    private User findOrCreateGoogleUser(GoogleUserInfo googleUserInfo) {
        Optional<User> existingUser = userRepository.findByEmail(googleUserInfo.getEmail());
        
        if (existingUser.isPresent()) {            
            return existingUser.get();
        } else {
            // Create new Google user
            return createNewGoogleUser(googleUserInfo);
        }
    }
    
    private User createNewGoogleUser(GoogleUserInfo googleUserInfo) {
        // Get default permission and role
        Permission defaultPermission = dataInitializationService.getDefaultPermission();
        Role defaultRole = dataInitializationService.getDefaultRole();
        
        Set<Permission> defaultPermissions = new HashSet<>();
        defaultPermissions.add(defaultPermission);
        
        Set<Role> defaultRoles = new HashSet<>();
        defaultRoles.add(defaultRole);
        
        User newUser = User.builder()
                .email(googleUserInfo.getEmail())
                .password("") // No password for Google users
                .firstName(googleUserInfo.getFirstName())
                .lastName(googleUserInfo.getLastName())
                .authProvider(AuthProvider.GOOGLE)
                .verified(true) // Trust Google's email verification
                .enabled(true)
                .userPermissions(defaultPermissions)
                .roles(defaultRoles)
                .build();
        
        return userRepository.save(newUser);
    }
}