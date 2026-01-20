package com.authx.service;

import com.authx.dto.request.AssignPermissionsRequest;
import com.authx.dto.request.AssignRolesRequest;
import com.authx.dto.response.UserDetailsResponse;
import com.authx.entity.Permission;
import com.authx.entity.Role;
import com.authx.entity.User;
import com.authx.repository.PermissionRepository;
import com.authx.repository.RoleRepository;
import com.authx.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;

    @PreAuthorize("hasRole('SUPER_ADMIN') and hasAuthority('ASSIGN_ROLES')")
    public UserDetailsResponse assignRolesToUser(AssignRolesRequest request) {
        User user = userRepository.findById(request.getUserId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        Set<Role> roles = new HashSet<>();
        for (Long roleId : request.getRoleIds()) {
            Role role = roleRepository.findById(roleId)
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Role not found with id: " + roleId));
            roles.add(role);
        }

        if (user.getRoles() == null) {
            user.setRoles(new HashSet<>());
        }
        user.getRoles().clear();
        user.getRoles().addAll(roles);
        user = userRepository.save(user);

        return mapToUserDetailsResponse(user);
    }

    @PreAuthorize("hasRole('SUPER_ADMIN') and hasAuthority('ASSIGN_PERMISSIONS')")
    public UserDetailsResponse assignPermissionsToUser(AssignPermissionsRequest request) {
        User user = userRepository.findById(request.getUserId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));

        Set<Permission> permissions = new HashSet<>();
        for (Long permissionId : request.getPermissionIds()) {
            Permission permission = permissionRepository.findById(permissionId)
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Permission not found with id: " + permissionId));
            permissions.add(permission);
        }

        if (user.getUserPermissions() == null) {
            user.setUserPermissions(new HashSet<>());
        }
        user.getUserPermissions().clear();
        user.getUserPermissions().addAll(permissions);
        user = userRepository.save(user);

        return mapToUserDetailsResponse(user);
    }

    public UserDetailsResponse getUserDetails(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
        
        return mapToUserDetailsResponse(user);
    }

    private UserDetailsResponse mapToUserDetailsResponse(User user) {
        return UserDetailsResponse.builder()
                .id(user.getId())
                .email(user.getEmail())
                .verified(user.getVerified())
                .enabled(user.getEnabled())
                .roles(user.getRoles() != null ? 
                    new HashSet<>(user.getRoles()).stream().map(Role::getName).collect(Collectors.toSet()) : 
                    new HashSet<>())
                .permissions(user.getUserPermissions() != null ? 
                    new HashSet<>(user.getUserPermissions()).stream().map(Permission::getName).collect(Collectors.toSet()) : 
                    new HashSet<>())
                .build();
    }
}