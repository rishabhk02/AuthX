package com.authx.repository;

import com.authx.entity.Permission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface PermissionRepository extends JpaRepository<Permission, Long> {
    Optional<Permission> findByName(String name);
    boolean existsByName(String name);

    @Query(
            value = """
                    SELECT DISTINCT p.*
                      FROM permissions p
                      LEFT JOIN user_permissions up ON p.id = up.permission_id
                      LEFT JOIN users_roles ur ON ur.user_id = :userId
                      LEFT JOIN role_permissions rp ON rp.role_id = ur.role_id
                     WHERE up.user_id = :userId
                        OR rp.permission_id = p.id
                    """,
            nativeQuery = true
    )
    List<Permission> findAllPermissionsForUser(Long userId);
}