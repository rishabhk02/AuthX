package com.authx.entity;

import jakarta.persistence.*;
import lombok.*;

import java.util.Set;

import com.authx.enums.AuthProvider;

@Data
@Builder
@Entity
@Table(name = "users")
@NoArgsConstructor
@AllArgsConstructor
public class User {
        @Id()
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private Long id;

        @Column(nullable = false)
        private String firstName;

        @Column(nullable = false)
        private String lastName;

        @Column(unique = true, nullable = false)
        private String email;

        @Column(nullable = true)
        private String password;

        @Builder.Default
        private Boolean verified = false;

        @ManyToMany(fetch = FetchType.EAGER)
        @JoinTable(name = "user_roles", // Join on user_roles junction table
                        joinColumns = @JoinColumn(name = "user_id"), // current table column id mapped to user_id
                        inverseJoinColumns = @JoinColumn(name = "role_id") // other table column id mapped to role_id
        )
        @EqualsAndHashCode.Exclude
        @ToString.Exclude
        private Set<Role> roles;

        @Builder.Default
        private Boolean enabled = true;

        @Enumerated(EnumType.STRING)
        @Column(nullable = false)
        @Builder.Default
        private AuthProvider authProvider = AuthProvider.EMAIL;

        @ManyToMany(fetch = FetchType.LAZY)
        @JoinTable(name = "user_permissions", joinColumns = @JoinColumn(name = "user_id"), inverseJoinColumns = @JoinColumn(name = "permission_id"))
        @EqualsAndHashCode.Exclude
        @ToString.Exclude
        private Set<Permission> userPermissions;
}