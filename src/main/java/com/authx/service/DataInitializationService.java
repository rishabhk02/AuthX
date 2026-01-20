package com.authx.service;

import com.authx.entity.Permission;
import com.authx.entity.Role;
import com.authx.entity.User;
import com.authx.repository.PermissionRepository;
import com.authx.repository.RoleRepository;
import com.authx.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
@Slf4j
@RequiredArgsConstructor
public class DataInitializationService {
    private final PermissionRepository permissionRepository;
    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    @PostConstruct
    public void initializeDefaultData() {
        log.info("Initializing default data...");
        
        // Create default permissions
        createDefaultPermissions();
        
        // Create default roles
        createDefaultRoles();
        
        // Create super admin user
        createSuperAdminUser();
        
        log.info("Default data initialization completed");
    }

    private void createDefaultPermissions() {
        String[] defaultPermissions = {
            "READ_USERS", "CREATE_USERS", "UPDATE_USERS", "DELETE_USERS",
            "READ_ROLES", "CREATE_ROLES", "UPDATE_ROLES", "DELETE_ROLES",
            "READ_PERMISSIONS", "CREATE_PERMISSIONS", "UPDATE_PERMISSIONS", "DELETE_PERMISSIONS",
            "ASSIGN_ROLES", "ASSIGN_PERMISSIONS", "MANAGE_SYSTEM"
        };

        for (String permissionName : defaultPermissions) {
            if (!permissionRepository.existsByName(permissionName)) {
                Permission permission = Permission.builder()
                        .name(permissionName)
                        .build();
                permissionRepository.save(permission);
                log.info("Created permission: {}", permissionName);
            }
        }
    }

    private void createDefaultRoles() {
        // Create USER role with basic permissions
        if (!roleRepository.existsByName("USER")) {
            Set<Permission> userPermissions = new HashSet<>();
            permissionRepository.findByName("READ_USERS").ifPresent(userPermissions::add);
            
            Role userRole = Role.builder()
                    .name("USER")
                    .permissions(userPermissions)
                    .build();
            roleRepository.save(userRole);
            log.info("Created USER role");
        }

        // Create ADMIN role with moderate permissions
        if (!roleRepository.existsByName("ADMIN")) {
            Set<Permission> adminPermissions = new HashSet<>();
            String[] adminPermissionNames = {"READ_USERS", "CREATE_USERS", "UPDATE_USERS", "READ_ROLES", "READ_PERMISSIONS"};
            
            for (String permName : adminPermissionNames) {
                permissionRepository.findByName(permName).ifPresent(adminPermissions::add);
            }
            
            Role adminRole = Role.builder()
                    .name("ADMIN")
                    .permissions(adminPermissions)
                    .build();
            roleRepository.save(adminRole);
            log.info("Created ADMIN role");
        }

        // Create SUPER_ADMIN role with all permissions
        if (!roleRepository.existsByName("SUPER_ADMIN")) {
            Set<Permission> allPermissions = new HashSet<>(permissionRepository.findAll());
            
            Role superAdminRole = Role.builder()
                    .name("SUPER_ADMIN")
                    .permissions(allPermissions)
                    .build();
            roleRepository.save(superAdminRole);
            log.info("Created SUPER_ADMIN role with all permissions");
        }
    }

    private void createSuperAdminUser() {
        String superAdminEmail = "superadmin@authx.com";
        String superAdminPassword = "AuthxAdmin@18";

        if (!userRepository.existsByEmail(superAdminEmail)) {
            Role superAdminRole = roleRepository.findByName("SUPER_ADMIN")
                    .orElseThrow(() -> new RuntimeException("SUPER_ADMIN role not found"));
            
            Set<Permission> allPermissions = new HashSet<>(permissionRepository.findAll());
            Set<Role> roles = new HashSet<>();
            roles.add(superAdminRole);

            User superAdmin = User.builder()
                    .email(superAdminEmail)
                    .password(passwordEncoder.encode(superAdminPassword))
                    .verified(true)
                    .enabled(true)
                    .roles(roles)
                    .userPermissions(allPermissions)
                    .build();

            userRepository.save(superAdmin);
            log.info("Created super admin user with email: {}", superAdminEmail);
        }
    }

    public Permission getDefaultPermission() {
        return permissionRepository.findByName("READ_USERS")
                .orElseThrow(() -> new RuntimeException("Default permission READ_USERS not found"));
    }

    public Role getDefaultRole() {
        return roleRepository.findByName("USER")
                .orElseThrow(() -> new RuntimeException("Default role USER not found"));
    }
}